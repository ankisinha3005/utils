import com.booking.salon.exception.PlatformValidationException
import mu.KLoggable
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.jcajce.*
import org.bouncycastle.util.io.Streams
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.SecureRandom
import java.util.*

object PGPUtils {

    object Logger : KLoggable {
        override val logger = logger()

    }
    fun pgpEncrypted(
            dataToEncrypt: ByteArray, encryptionKey: InputStream, logCleaner: String.() -> String = { this }
    ): ByteArray {
        Logger.logger.info {
            "Data To be Encrypted: ${dataToEncrypt.toString(Charsets.UTF_8).logCleaner()}"
        }
        ByteArrayOutputStream().use { encryptionOutput ->
            ByteArrayOutputStream().use { bOut ->
                PGPLiteralDataGenerator()
                        .open(
                                bOut,
                                PGPLiteralData.BINARY,
                                PGPLiteralData.CONSOLE,
                                dataToEncrypt.size.toLong(),
                                Date()
                        ).use {
                            it.write(dataToEncrypt)
                        }

                ArmoredOutputStream(encryptionOutput).use { armoredOut ->
                    PGPEncryptedDataGenerator(
                            JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                                    .setWithIntegrityPacket(false)
                                    .setSecureRandom(SecureRandom())
                                    .setProvider("BC")
                    )
                            .apply {
                                addMethod(
                                        JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey.toPGPPublicKey()).setProvider(
                                                "BC"
                                        )
                                )
                            }
                            .open(armoredOut, bOut.size().toLong())
                            .use {
                                it.write(bOut.toByteArray())
                            }
                }

                return encryptionOutput.toByteArray()
            }
        }
    }


    fun pgpDecrypted(dataToDecrypt: InputStream, decryptionKey: InputStream, logCleaner: String.() -> String = { this }): ByteArray {
        val encryptedData =
                JcaPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(dataToDecrypt.readBytes())))
                        .first { it is PGPEncryptedDataList }
                        .let { it as PGPEncryptedDataList }
                        .encryptedDataObjects
                        .next() as PGPPublicKeyEncryptedData

        val pgpLiteralData = encryptedData.getDataStream(
                JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider("BC")
                        .build(decryptionKey.toPGPPrivateKey())
        ).let {
            JcaPGPObjectFactory(it)
        }.nextObject()
                .let {
                    it as PGPCompressedData
                    JcaPGPObjectFactory(it.dataStream).nextObject() as PGPLiteralData
                }

        return ByteArrayOutputStream()
                .use {
                    Streams.pipeAll(pgpLiteralData.inputStream, it)
                    it.toByteArray()
                }.also {
                    Logger.logger.info {
                        "Decrypted Data: ${it.toString(Charsets.UTF_8).logCleaner()}"
                    }
                }
    }

    private fun InputStream.toPGPPublicKey(): PGPPublicKey =
            PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(this), JcaKeyFingerprintCalculator()
            ).keyRings
                    .asSequence()
                    .flatMap { it.publicKeys.asSequence() }
                    .firstOrNull { it.isEncryptionKey }
                    ?: throw PlatformValidationException("Can't find encryption key in key ring.")

    private fun InputStream.toPGPPrivateKey(): PGPPrivateKey =
            PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(this), JcaKeyFingerprintCalculator()
            ).keyRings
                    .asSequence()
                    .flatMap { it.secretKeys.asSequence() }
                    .firstOrNull { it.isSigningKey }
                    ?.extractPrivateKey(
                            JcePBESecretKeyDecryptorBuilder()
                                    .setProvider("BC")
                                    .build(charArrayOf())
                    )
                    ?: throw PlatformValidationException("Can't find decryption key in key ring.")

}

