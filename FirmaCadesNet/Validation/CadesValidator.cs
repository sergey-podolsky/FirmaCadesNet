﻿// --------------------------------------------------------------------------------------------------------------------
// CadesValidator.cs
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

using FirmaCadesNet.Crypto;
using FirmaCadesNet.Signature;
using System;
using System.Linq;

namespace FirmaCadesNet.Validation
{
    public class CadesValidator
    {
        public ValidationResult Validate(SignatureDocument sigDocument, SignerInfoNode signerNode)
        {
            ValidationResult result = new ValidationResult();

            try
            {               
                if (!signerNode.SignerInformation.Verify(signerNode.Certificate))
                {
                    result.IsValid = false;
                    result.Message = "Signature verification failed";

                    return result;
                }

                if (signerNode.TimeStamp != null)
                {
                    DigestMethod tokenDigestMethod = DigestMethod.GetByOid(signerNode.TimeStamp.TimeStampInfo.HashAlgorithm.ObjectID.Id);
                    byte[] signatureValueHash = tokenDigestMethod.CalculateDigest(signerNode.SignerInformation.GetSignature());

                    if (!signerNode.TimeStamp.TimeStampInfo.GetMessageImprintDigest().SequenceEqual(signatureValueHash))
                    {
                        result.IsValid = false;
                        result.Message = "The stamp of the time stamp does not correspond to the one calculated";

                        return result;
                    }
                }     

                result.IsValid = true;
                result.Message = "Signature verification suceeded";

            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Message = ex.Message;
            }

            return result;
        }
    }
}
