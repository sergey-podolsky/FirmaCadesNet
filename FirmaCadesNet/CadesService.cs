// --------------------------------------------------------------------------------------------------------------------
// CadesService.cs
//
// FirmaCadesNet - Librería para la generación de firmas CAdES
// Copyright (C) 2017 Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/. 
//
// E-Mail: informatica@gemuc.es
// 
// --------------------------------------------------------------------------------------------------------------------

using crypto.src.crypto.signers;
using FirmaCadesNet.Crypto;
using FirmaCadesNet.Signature;
using FirmaCadesNet.Signature.Parameters;
using FirmaCadesNet.Util;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace FirmaCadesNet
{
    public class CadesService
    {
        #region Public methods

        /// <summary>
        /// Sign the input content. It also accepts the value of the input content footprint
        /// </summary>
        /// <param name="input"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public SignatureDocument Sign(Stream input, SignatureParameters parameters)
        {
            CheckParameters(parameters);

            if (input == null && parameters.PreCalculatedDigest == null)
            {
                throw new Exception("Content to sign needs to be specified");
            }

            return ComputeSignature(input, parameters, null);
        }

        /// <summary>
        /// Sign the input content. It also accepts the value of the input content footprint
        /// </summary>
        /// <param name="input"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public SignatureDocument Sign(byte[] input, SignatureParameters parameters)
        {
            CheckParameters(parameters);

            if (input == null && parameters.PreCalculatedDigest == null)
            {
                throw new Exception("Content to sign needs to be specified");
            }

            return ComputeSignature(input, parameters, null);
        }

        /// <summary>
        /// Apply a co-signature to an existing CAdES signature
        /// </summary>
        /// <param name="sigDocument"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public SignatureDocument CoSign(SignatureDocument sigDocument, SignatureParameters parameters)
        {
            if (sigDocument == null)
            {
                throw new Exception("Previous signature is needed to confirm");
            }

            CheckParameters(parameters);

            return ComputeSignature(sigDocument.Content, parameters, sigDocument.SignedData);
        }

        /// <summary>
        /// Make the counter signature of an existing CAdES signature
        /// </summary>
        /// <param name="sigDocument"></param>
        /// <param name="signerInfoNode"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public SignatureDocument CounterSign(SignatureDocument sigDocument, SignerInfoNode signerInfoNode, SignatureParameters parameters)
        {
            if (sigDocument == null)
            {
                throw new Exception("A prior signature is needed to perform co-sign");
            }

            if (signerInfoNode == null)
            {
                throw new Exception("Signature node needs to be specified to apply counter signature");
            }

            CheckParameters(parameters);

            byte[] signature = null;

            using (MemoryStream ms = new MemoryStream(signerInfoNode.SignerInformation.GetSignature()))
            {
                byte[] toBeSigned = ToBeSigned(new CmsProcessableInputStream(ms), parameters, null, true);
                signature = parameters.Signer.SignData(toBeSigned, parameters.DigestMethod);
            }

            CustomCMSSignedDataGenerator generator = CreateSignedGenerator(new PreComputedSigner(signature), parameters, null);

            var result = generator.GenerateCounterSigners(signerInfoNode.SignerInformation);

            SignerInformation updatedSI = SignerInformation.AddCounterSigners(signerInfoNode.SignerInformation, result);

            List<X509Certificate> certs = new List<X509Certificate>();
            IX509Store originalCertStore = sigDocument.SignedData.GetCertificates("Collection");

            signerInfoNode.SignerInformation = updatedSI;

            CollectionUtilities.AddRange(certs, GetCertificatesFromStore(originalCertStore));

            X509CertificateParser parser = new X509CertificateParser();
            var signerCertificate = parser.ReadCertificate(parameters.Certificate.GetRawCertData());

            if (!CheckCertExists(signerCertificate, originalCertStore))
            {
                certs.Add(signerCertificate);
            }

            IX509Store certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(certs));

            CmsSignedData newSignedData = CmsSignedData.ReplaceCertificatesAndCrls(sigDocument.SignedData, certStore, sigDocument.SignedData.GetCrls("Collection"), null);

            return new SignatureDocument(newSignedData);
        }

        public SignatureDocument Load(Stream input)
        {
            return new SignatureDocument(new CmsSignedData(input));
        }

        public SignatureDocument Load(string fileName)
        {
            using (FileStream fs = new FileStream(fileName, FileMode.Open))
            {
                return Load(fs);
            }
        }

        #endregion

        #region Private methods

        private void CheckParameters(SignatureParameters parameters)
        {
            if (parameters == null)
            {
                throw new Exception("The parameters to generate the signature are mandatory");
            }

            if (parameters.Signer == null)
            {
                throw new Exception("Signer was not specified to generate the signaturea");
            }

            if (parameters.Certificate == null)
            {
                throw new Exception("Certificate was not specified");
            }
        }

        /// <summary>
        /// Method to create signature generator
        /// </summary>
        /// <param name="signerProvider"></param>
        /// <param name="parameters"></param>
        /// <param name="originalSignedData"></param>
        /// <returns></returns>
        private CustomCMSSignedDataGenerator CreateSignedGenerator(ISigner signerProvider,
            SignatureParameters parameters, CmsSignedData originalSignedData)
        {
            X509CertificateParser parser = new X509CertificateParser();
            var signerCertificate = parser.ReadCertificate(parameters.Certificate.GetRawCertData());

            CustomCMSSignedDataGenerator generator = new CustomCMSSignedDataGenerator();

            Dictionary<DerObjectIdentifier, Asn1Encodable> signedAttrDic = GetSignedAttributes(parameters);

            if (!signedAttrDic.ContainsKey(PkcsObjectIdentifiers.IdAAContentHint) &&
                originalSignedData != null)
            {
                var attrContentHint = GetContentHintAttribute(originalSignedData.GetSignerInfos());

                if (attrContentHint != null)
                {
                    signedAttrDic.Add(PkcsObjectIdentifiers.IdAAContentHint, attrContentHint);
                }
            }

            CmsAttributeTableGenerator signedAttrGen = new DefaultSignedAttributeTableGenerator
                    (new Org.BouncyCastle.Asn1.Cms.AttributeTable(signedAttrDic));

            generator.SignerProvider = signerProvider;
            generator.AddSigner(new NullPrivateKey(), signerCertificate,
                PkcsObjectIdentifiers.RsaEncryption.Id, parameters.DigestMethod.Oid, signedAttrGen, null);

            if (originalSignedData != null)
            {
                generator.AddSigners(originalSignedData.GetSignerInfos());
            }

            bool addSignerCert = true;

            if (originalSignedData != null)
            {
                IX509Store originalCertStore = originalSignedData.GetCertificates("Collection");

                generator.AddCertificates(originalCertStore);

                addSignerCert = !CheckCertExists(signerCertificate, originalCertStore);
            }

            if (addSignerCert)
            {
                List<X509Certificate> certs = new List<X509Certificate>();
                certs.Add(signerCertificate);

                IX509Store certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(certs));
                generator.AddCertificates(certStore);
            }

            return generator;
        }

        /// <summary>
        /// Returns a list of the certificates contained in a certificate store
        /// </summary>
        /// <param name="certStore"></param>
        /// <returns></returns>
        private IList GetCertificatesFromStore(IX509Store certStore)
        {
            try
            {
                IList certs = new List<object>();

                if (certStore != null)
                {
                    foreach (X509Certificate c in certStore.GetMatches(null))
                    {
                        certs.Add(c);
                    }
                }

                return certs;
            }
            catch (CertificateEncodingException e)
            {
                throw new CmsException("error encoding certs", e);
            }
            catch (Exception e)
            {
                throw new CmsException("error processing certs", e);
            }
        }

        /// <summary>
        /// Check if a certificate already exists in a given store
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="certStore"></param>
        /// <returns></returns>
        private bool CheckCertExists(X509Certificate cert, IX509Store certStore)
        {
            X509CertStoreSelector selector = new X509CertStoreSelector();
            selector.Certificate = cert;
            ICollection result = certStore.GetMatches(selector);

            if (result == null)
            {
                return false;
            }
            else
            {
                return result.Count > 0;
            }
        }

        /// <summary>
        /// Method to create the attribute that contains the certificate information used for the signature
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private BcCms.Attribute MakeSigningCertificateAttribute(SignatureParameters parameters)
        {
            X509Certificate certificate = new X509CertificateParser().ReadCertificate(parameters.Certificate.GetRawCertData());
            TbsCertificateStructure tbs = TbsCertificateStructure.GetInstance(
                                Asn1Object.FromByteArray(
                                certificate.GetTbsCertificate()));
            GeneralName gn = new GeneralName(tbs.Issuer);
            GeneralNames gns = new GeneralNames(gn);
            IssuerSerial issuerSerial = new IssuerSerial(gns, tbs.SerialNumber);

            byte[] certHash = DigestUtilities.CalculateDigest(parameters.DigestMethod.Name, certificate.GetEncoded());

            var policies = GetPolicyInformation(certificate);

            if (parameters.DigestMethod == DigestMethod.SHA1)
            {
                SigningCertificate sc = null;

                if (policies != null)
                {
                    Asn1EncodableVector v = new Asn1EncodableVector();
                    v.Add(new DerSequence(new EssCertID(certHash, issuerSerial)));
                    v.Add(new DerSequence(policies));
                    sc = SigningCertificate.GetInstance(new DerSequence(v));
                }
                else
                {
                    sc = new SigningCertificate(new EssCertID(certHash, issuerSerial));
                }

                return new BcCms.Attribute(PkcsObjectIdentifiers.IdAASigningCertificate, new DerSet(sc));
            }
            else
            {
                EssCertIDv2 essCert = new EssCertIDv2(AlgorithmIdentifier.GetInstance(parameters.DigestMethod
                    .Oid), certHash, issuerSerial);

                SigningCertificateV2 scv2 = new SigningCertificateV2(new EssCertIDv2[] { essCert }, policies);

                return new BcCms.Attribute(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet
                    (scv2));
            }
        }

        /// <summary>
        /// Returns the policy information of a certificate
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        private PolicyInformation[] GetPolicyInformation(X509Certificate cert)
        {
            Asn1OctetString extensionValue = cert.GetExtensionValue(new DerObjectIdentifier("2.5.29.32"));
            if (extensionValue == null) return null;

            byte[] certPolicies = extensionValue.GetOctets();

            return CertificatePolicies.GetInstance(certPolicies).GetPolicyInformation();
        }


        /// <summary>
        /// Method to create the attribute that contains the signature date
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private BcCms.Attribute MakeSigningTimeAttribute(SignatureParameters parameters)
        {
            return new BcCms.Attribute(PkcsObjectIdentifiers.Pkcs9AtSigningTime, new DerSet(new
                DerUtcTime(parameters.SigningDate.ToUniversalTime())));
        }

        /// <summary>
        /// Method to create the attribute that contains the signer's role
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private BcCms.Attribute MakeSignerAttrAttribute(SignatureParameters parameters)
        {
            DerUtf8String[] roles = new DerUtf8String[1];
            roles[0] = new DerUtf8String(parameters.SignerRole);

            BcCms.Attribute claimedRolesAttr = new BcCms.Attribute(X509ObjectIdentifiers.id_at_name, new DerSet(roles));

            return new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsSignerAttr, new DerSet(new SignerAttribute
                (new DerSequence(claimedRolesAttr))));
        }

        /// <summary>
        /// Method to create the attribute that contains the location information
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private BcCms.Attribute MakeSignerLocationAttribute(SignatureParameters parameters)
        {
            List<Asn1Encodable> postalAddressList = null;

            if (!string.IsNullOrEmpty(parameters.SignatureProductionPlace.PostalCode))
            {
                postalAddressList = new List<Asn1Encodable>();
                postalAddressList.Add(new DerUtf8String(parameters.SignatureProductionPlace.PostalCode));
            }

            SignerLocation sigLocation = new SignerLocation(
                !string.IsNullOrEmpty(parameters.SignatureProductionPlace.CountryName) ? new DerUtf8String(parameters.SignatureProductionPlace.CountryName) : null,
                !string.IsNullOrEmpty(parameters.SignatureProductionPlace.City) ? new DerUtf8String(parameters.SignatureProductionPlace.City) : null,
                postalAddressList != null ? new DerSequence(postalAddressList.ToArray()) : null
                );

            return new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsSignerLocation, new DerSet(sigLocation));
        }

        /// <summary>
        /// Method to create the attribute that contains the information about the signer's action on the signed document
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private IEnumerable<BcCms.Attribute> MakeCommitmentTypeIndicationAttributes(SignatureParameters parameters)
        {
            List<Asn1Encodable> commitments = new List<Asn1Encodable>();

            foreach (var commitmentType in parameters.SignatureCommitments)
            {
                List<Asn1Encodable> qualifiers = new List<Asn1Encodable>();

                foreach (var qualifier in commitmentType.CommitmentTypeQualifiers)
                {
                    qualifiers.Add(new DerObjectIdentifier(qualifier));
                }

                commitments.Add(new CommitmentTypeIndication(commitmentType.CommitmentType.Oid, new DerSequence(qualifiers.ToArray())));
            }

            List<BcCms.Attribute> attributes = new List<BcCms.Attribute>();
            foreach (var commitmentType in commitments)
            {
                attributes.Add(new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsCommitmentType, new DerSet(commitmentType)));
            }

            return attributes;
        }

        /// <summary>
        /// Method to create the attribute that contains the information about the signature policy
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private BcCms.Attribute MakeSignaturePolicyAttribute(SignatureParameters parameters)
        {
            SignaturePolicyIdentifier sigPolicy = new SignaturePolicyIdentifier(new SignaturePolicyId(new DerObjectIdentifier
(parameters.SignaturePolicyInfo.PolicyIdentifier), new OtherHashAlgAndValue(new AlgorithmIdentifier(new DerObjectIdentifier(parameters.SignaturePolicyInfo.PolicyDigestAlgorithm.Oid)),
   new DerOctetString(System.Convert.FromBase64String(parameters.SignaturePolicyInfo.PolicyHash)))));
            return new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsSigPolicyID, new DerSet(sigPolicy));
        }

        /// <summary>
        /// Method that returns the attributes that must be signed
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private Dictionary<DerObjectIdentifier, Asn1Encodable> GetSignedAttributes(SignatureParameters parameters)
        {
            Dictionary<DerObjectIdentifier, Asn1Encodable> signedAttrs = new Dictionary<DerObjectIdentifier, Asn1Encodable>();

            BcCms.Attribute signingCertificateReference = MakeSigningCertificateAttribute(parameters);

            signedAttrs.Add((DerObjectIdentifier)signingCertificateReference.AttrType,
                signingCertificateReference);

            signedAttrs.Add(PkcsObjectIdentifiers.Pkcs9AtSigningTime, MakeSigningTimeAttribute
                (parameters));

            if (parameters.SignaturePolicyInfo != null)
            {
                signedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsSigPolicyID, MakeSignaturePolicyAttribute(parameters));
            }

            if (!string.IsNullOrEmpty(parameters.SignerRole))
            {
                signedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsSignerAttr, MakeSignerAttrAttribute(parameters));
            }

            if (parameters.SignatureProductionPlace != null)
            {
                signedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsSignerLocation, MakeSignerLocationAttribute(parameters));
            }

            if (parameters.SignatureCommitments.Count > 0)
            {
                var commitments = MakeCommitmentTypeIndicationAttributes(parameters);

                foreach (var item in commitments)
                {
                    signedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsCommitmentType, item);
                }
            }

            if (!string.IsNullOrEmpty(parameters.MimeType))
            {
                ContentHints contentHints = new ContentHints(new DerObjectIdentifier(MimeTypeHelper.GetMimeTypeOid(parameters.MimeType)));

                BcCms.Attribute contentAttr = new BcCms.Attribute(PkcsObjectIdentifiers.IdAAContentHint, new DerSet(contentHints));
                signedAttrs.Add(PkcsObjectIdentifiers.IdAAContentHint, contentAttr);
            }

            return signedAttrs;
        }

        /// <summary>
        /// Returns the final data that must be signed
        /// </summary>
        /// <param name="content"></param>
        /// <param name="parameters"></param>
        /// <param name="signedData"></param>
        /// <param name="isCounterSignature"></param>
        /// <returns></returns>
        private byte[] ToBeSigned(CmsProcessable content, SignatureParameters parameters, CmsSignedData signedData, bool isCounterSignature)
        {
            PreComputedSigner preComputedSigner = new PreComputedSigner();
            CustomCMSSignedDataGenerator generator = CreateSignedGenerator(preComputedSigner, parameters, signedData);

            if (parameters.PreCalculatedDigest != null)
            {
                generator.PreCalculatedDigest = parameters.PreCalculatedDigest;
            }
            else if (content == null)
            {
                // If the content is null, try to find the value of the content footprint in the other firms
                generator.PreCalculatedDigest = GetDigestValue(signedData.GetSignerInfos(), parameters.DigestMethod);

                if (generator.PreCalculatedDigest == null)
                {
                    throw new Exception("Could not get the footprint of the content");
                }
            }

            generator.PreGenerate(!isCounterSignature ? CmsObjectIdentifiers.Data.Id : null, content);

            return preComputedSigner.CurrentSignature();
        }

        /// <summary>
        /// Method that searches the other signatures for the message-digest that matches the given fingerprint algorithm
        /// </summary>
        /// <param name="siStore"></param>
        /// <param name="digestMethod"></param>
        /// <returns></returns>
        private byte[] GetDigestValue(SignerInformationStore siStore, DigestMethod digestMethod)
        {
            var signers = siStore.GetSigners();

            foreach (SignerInformation signerInfo in signers)
            {
                if (signerInfo.DigestAlgOid == digestMethod.Oid)
                {
                    BcCms.Attribute digest = signerInfo.SignedAttributes[PkcsObjectIdentifiers.Pkcs9AtMessageDigest];
                    DerOctetString derHash = (DerOctetString)digest.AttrValues[0];

                    return derHash.GetOctets();
                }
            }

            return null;
        }

        /// <summary>
        /// Method that searches the other signatures for the type of signed content
        /// </summary>
        /// <param name="siStore"></param>
        /// <returns></returns>
        private BcCms.Attribute GetContentHintAttribute(SignerInformationStore siStore)
        {
            var signers = siStore.GetSigners();

            foreach (SignerInformation signerInfo in signers)
            {
                BcCms.Attribute contentHint = signerInfo.SignedAttributes[PkcsObjectIdentifiers.IdAAContentHint];

                if (contentHint != null)
                {
                    return contentHint;
                }
            }

            return null;
        }

        private SignatureDocument ComputeSignature(byte[] input, SignatureParameters parameters, CmsSignedData signedData)
		{
			CmsProcessableByteArray content = null;

            if (input != null)
            {
				content = new CmsProcessableByteArray(input);
			}

            return ComputeSignature(content, parameters, signedData);
		}

        private SignatureDocument ComputeSignature(Stream input, SignatureParameters parameters, CmsSignedData signedData)
        {
            CmsProcessableByteArray content = null;

            if (input != null)
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    const int bufferSize = 1024;
                    byte[] buffer = new byte[bufferSize];
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                        ms.Write(buffer, 0, read);
                    content = new CmsProcessableByteArray(ms.ToArray());
                }
            }

            return ComputeSignature(content, parameters, signedData);
        }

        /// <summary>
        /// Method that performs the signing process
        /// </summary>
        /// <param name="input"></param>
        /// <param name="parameters"></param>
        /// <param name="signedData"></param>
        /// <returns></returns>
        private SignatureDocument ComputeSignature(CmsProcessableByteArray content, SignatureParameters parameters, CmsSignedData signedData)
        {
            byte[] toBeSigned = ToBeSigned(content, parameters, signedData, false);
            byte[] signature = parameters.Signer.SignData(toBeSigned, parameters.DigestMethod);

            PreComputedSigner preComputedSigner = new PreComputedSigner(signature);
            CustomCMSSignedDataGenerator generator = CreateSignedGenerator(preComputedSigner, parameters, signedData);
            CmsSignedData newSignedData = null;

            if (parameters.SignaturePackaging == SignaturePackaging.ATTACHED_IMPLICIT && parameters.PreCalculatedDigest == null)
            {
                newSignedData = generator.Generate(content, true);
            }
            else
            {
                if (parameters.PreCalculatedDigest != null)
                {
                    generator.PreCalculatedDigest = parameters.PreCalculatedDigest;

                    newSignedData = generator.Generate(null, false);
                }
                else if (content != null)
                {
                    newSignedData = generator.Generate(content, false);
                }
                else
                {
                    generator.PreCalculatedDigest = GetDigestValue(signedData.GetSignerInfos(), parameters.DigestMethod);

                    newSignedData = generator.Generate(null, false);
                }
            }

            return new SignatureDocument(new CmsSignedData(newSignedData.GetEncoded()));
        }

        #endregion
    }
}
