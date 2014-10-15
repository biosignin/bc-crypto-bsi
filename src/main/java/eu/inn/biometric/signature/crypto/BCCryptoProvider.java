package eu.inn.biometric.signature.crypto;

/*
 * #%L
 * BC Crypto Provider for BioSignIn [http://www.biosignin.org]
 * BCCryptoProvider.java is part of BioSignIn project
 * %%
 * Copyright (C) 2014 Innovery SpA
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */


import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class BCCryptoProvider implements ICryptoProvider {

	@Override
	public byte[] encrypt(byte[] toEncrypt, List<X509Certificate> certs, Integer maxKeyLength) throws Exception {
		int keySize = Cipher.getMaxAllowedKeyLength("AES");
		if (maxKeyLength != null)
			if (keySize > maxKeyLength)
				keySize = maxKeyLength;
		String algIdentifier = CMSAlgorithm.AES128_CBC.getId();
		if (keySize >= 256)
			algIdentifier = CMSAlgorithm.AES256_CBC.getId();
		CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
		for (X509Certificate cert : certs)
			gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert));
		CMSTypedData data = new CMSProcessableByteArray(toEncrypt);
		CMSEnvelopedData enveloped = gen.generate(data, new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(
				algIdentifier)).build());
		return enveloped.getEncoded();
	}

	@Override
	public byte[] decrypt(byte[] data, PrivateKey key) {
		try {

			CMSEnvelopedData enveloped = new CMSEnvelopedData(data);

			for (Object recip : enveloped.getRecipientInfos().getRecipients()) {
				try {
					KeyTransRecipientInformation rinfo = (KeyTransRecipientInformation) recip;
					byte[] decryptedDocument = rinfo.getContent(new JceKeyTransEnvelopedRecipient(key));
					return decryptedDocument;
				} catch (Exception ex) {
				}
			}
			throw new RuntimeException("Cannot decrypt");

		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	@Override
	public byte[] b64Encode(byte[] data) {
		return Base64.encode(data);
	} 

	@Override
	public byte[] b64Decode(byte[] data) {
		return Base64.decode(data);
	}

	@Override
	public void addProvider() {
		if (Security.getProvider("BC") == null)
			Security.addProvider(new BouncyCastleProvider());

	}

}
