package com.karasiq.tls

import java.net.InetSocketAddress
import java.nio.channels.SocketChannel
import java.security.SecureRandom

import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.internal.{SocketChannelWrapper, TLSUtils}
import com.karasiq.tls.x509.CertificateVerifier
import org.bouncycastle.tls._
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.{BcDefaultTlsCredentialedSigner, BcTlsCrypto}

import scala.concurrent.Await
import scala.concurrent.duration._
import scala.language.postfixOps

class TLSClientWrapper(verifier: CertificateVerifier, address: InetSocketAddress = null, keySet: TLS.KeySet = null) extends TLSConnectionWrapper {
  protected def getClientCertificate(certificateRequest: CertificateRequest): Option[TLS.CertificateKey] = {
    if (keySet == null) None
    else TLSUtils.certificateFor(keySet, certificateRequest)
  }

  override def apply(connection: SocketChannel): SocketChannel = {
    val protocol = new TlsClientProtocol(SocketChannelWrapper.inputStream(connection), SocketChannelWrapper.outputStream(connection))
    val crypto = new BcTlsCrypto(SecureRandom.getInstanceStrong)
    val client = new DefaultTlsClient(crypto) {
      @volatile
      protected var selectedCipherSuite = 0

      override def getSupportedVersions: Array[ProtocolVersion] = {
        TLSUtils.maxVersion().downTo(TLSUtils.minVersion())
      }

      override def getCipherSuites: Array[Int] = {
        TLSUtils.defaultCipherSuites()
      }

      override def notifySelectedCipherSuite(selectedCipherSuite: Int): Unit = {
        this.selectedCipherSuite = selectedCipherSuite
      }

      override def notifyHandshakeComplete(): Unit = {
        handshake.trySuccess(true)
        this.cipherSuites
        onInfo(s"Selected cipher suite: ${CipherSuiteId.asString(selectedCipherSuite)}")
      }

      override def getAuthentication: TlsAuthentication = new TlsAuthentication {
        override def getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials = wrapException("Could not provide client credentials") {
          getClientCertificate(certificateRequest)
            .map(ck ⇒ new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), crypto, ck.key.getPrivate, ck.certificateChain, TLSUtils.signatureAlgorithm(ck.key.getPrivate))) // Ignores certificateRequest data
            .orNull
        }

        override def notifyServerCertificate(serverCertificate: TlsServerCertificate): Unit = wrapException("Server certificate error") {
          val chain: List[TLS.Certificate] = serverCertificate.getCertificate.getCertificateList.toList.map(_.toCertificate)

          if (chain.nonEmpty) {
            onInfo(s"Server certificate chain: ${chain.map(_.getSubject).mkString("; ")}")
            if (address != null && !verifier.isHostValid(chain.head, address.getHostString)) {
              val message = s"Certificate hostname not match: ${address.getHostString}"
              val exc = new TlsFatalAlert(AlertDescription.bad_certificate, new TLSException(message))
              onError(message, exc)
              throw exc
            }
          }

          if (!verifier.isChainValid(chain)) {
            val message = s"Invalid server certificate: ${chain.headOption.fold("<none>")(_.getSubject.toString)}"
            val exc = new TlsFatalAlert(AlertDescription.bad_certificate, new TLSException(message))
            onError(message, exc)
            throw exc
          }
        }
      }
    }

    val socket = wrapException(s"Error connecting to server: $address") {
      protocol.connect(client)
      new SocketChannelWrapper(connection, protocol)
    }
    Await.result(handshake.future, 3 minutes) // Wait for handshake
    socket
  }
}
