package philipsair;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import java.util.function.Consumer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// INFO use dead man switch as client will simply no longer receive observations when device goes offline
// INFO CoapClient.setExecutors() allows reuse of external executors provided by OpenHAB
// INFO CoapClient.setTimeout() allows to change timeouts for blocking transactions
// INFO library writes Californium.properties, which should probably be disabled when integrating with OpenHAB

public final class PhilipsAir {

    private static final String ENCODING = "UTF-8";

    private static final Logger logger = LoggerFactory.getLogger(PhilipsAir.class);
    private static final Random random = new Random();

    private final String host;
    private final String secret;
    private final Consumer<String> statusConsumer;

    private CoapClient syncClient;
    private CoapClient statusClient;
    private CoapClient controlClient;
    private CoapObserveRelation statusObserveRelation;

    private long lastClientId = random.nextInt();
    private long lastServerId = 0;

    private PhilipsAir(final String host, final String secret, final Consumer<String> statusConsumer) {
        this.host = host;
        this.secret = secret;
        this.statusConsumer = statusConsumer;
    }

    public void initialize() throws ConnectorException, IOException {
        logger.info("initializing");

        NetworkConfig.getStandard().setString(NetworkConfig.Keys.DEDUPLICATOR, NetworkConfig.Keys.NO_DEDUPLICATOR);

        syncClient = new CoapClient("coap", host, 5683, "sys/dev/sync");
        statusClient = new CoapClient("coap", host, 5683, "sys/dev/status");
        controlClient  = new CoapClient("coap", host, 5683, "sys/dev/control");
        sync();
        observe();
    }

    public void dispose() {
        logger.info("disposing");
        if (statusObserveRelation != null) {
            statusObserveRelation.proactiveCancel();
        }
        controlClient.shutdown();
        statusClient.shutdown();
        syncClient.shutdown();
    }

    private void sync() throws IOException, ConnectorException {
        logger.info("synchronizing with {}", syncClient.getURI());
        final CoapResponse response = syncClient.post(toHex(lastClientId), 0);
        if (response == null) {
            throw new IOException("synchronization failed as device is unreachable");
        }
        if (!ResponseCode.isSuccess(response.getCode())) {
            throw new IOException("synchronization failed with status " + response.getCode());
        }
        lastServerId = fromHex(response.getResponseText());
        logger.info("synchronized with client id {} and server id {}", toHex(lastClientId), toHex(lastServerId));
    }

    private void observe() {
        logger.info("observing {}", statusClient.getURI());
        statusObserveRelation = statusClient.observe(new CoapHandler() {
            @Override
            public void onLoad(final CoapResponse response) {
                if (response == null) {
                    logger.warn("ignoring empty observation");
                } else if (!ResponseCode.CONTENT.equals(response.getCode())) {
                    logger.warn("received unexpected observation status {}", response.getCode());
                } else {
                    logger.debug("received encrypted observation {}", response.getResponseText());
                    receive(response.getResponseText());
                }
            }
            @Override
            public void onError() {
                logger.warn("connector reported communication error");
            }
        });
    }

    private void receive(final String message) {
        // verify message length and split into compontents
        if (message.length() < 8 + 64) {
            logger.warn("ignoring message with unexpected length");
            return;
        }            
        final String id = message.substring(0, 8);
        final String content = message.substring(8, message.length() - 64);
        final String digest = message.substring(message.length() - 64);
        // verify and increment message id
        if (!id.equals(toHex(lastClientId + 1))) {
            logger.warn("ignoring message with unexpected message id");
            return;
        }
        ++lastClientId;
        // verify digest
        if (!digest.equals(digest(id + content))) {
            logger.warn("ignoring message with mismatching digest");
            return;            
        }
        // decrypt content and pass to consumer
        final String decrypted = decrypt(secret + id, content);
        logger.debug("received observation {}", decrypted);
        statusConsumer.accept(decrypted);
    }

    public String send(final String content) throws IOException, ConnectorException {
        logger.debug("sending message {}", content);
        final String id = toHex(++lastServerId);
        final String encrypted = encrypt(secret + id, content);
        final String digest = digest(id + encrypted);
        final String message = id + encrypted + digest;
        logger.debug("sending encrypted message {}", message);
        final CoapResponse response = controlClient.post(message, 0);
        if (response == null) {
            throw new IOException("sending failed as device is unreachable");
        }
        if (!ResponseCode.isSuccess(response.getCode())) {
            throw new IOException("sending failed with status " + response.getCode());
        }
        logger.debug("received response {}", response.getResponseText());
        return response.getResponseText();
    }

    private static final String encrypt(final String key, final String data) throws IOException {
        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            final byte[] keyAndIv = md.digest(key.getBytes(ENCODING));
            final SecretKeySpec keySpec = new SecretKeySpec(toHexBinary(keyAndIv, 0, 8).getBytes(ENCODING), "AES");
            final IvParameterSpec ivSpec = new IvParameterSpec(toHexBinary(keyAndIv, 8, 8).getBytes(ENCODING));
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            return toHexBinary(cipher.doFinal(data.getBytes(ENCODING)));
        }
        catch (final Exception e) {
            throw new IOException("message encryption failed", e);
        }
    }

    private static final String decrypt(final String key, final String data) {
        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            final byte[] keyAndIv = md.digest(key.getBytes(ENCODING));
            final SecretKeySpec keySpec = new SecretKeySpec(toHexBinary(keyAndIv, 0, 8).getBytes(ENCODING), "AES");
            final IvParameterSpec ivSpec = new IvParameterSpec(toHexBinary(keyAndIv, 8, 8).getBytes(ENCODING));
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            return new String(cipher.doFinal(fromHexBinary(data)), ENCODING);
        } catch (final Exception e) {
            throw new RuntimeException("message decryption failed", e);
        }
    }

    private static final String digest(final String data) {
        try {        
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHexBinary(digest.digest(data.getBytes(ENCODING)));
        } catch (final Exception e) {
            throw new RuntimeException("message digest failed", e);
        }
    }

    private static long fromHex(final String value) {
        return Long.valueOf(value, 16) & 0xFFFFFFFF;
    }

    private static String toHex(final long value) {
        return StringUtils.leftPad(Integer.toHexString((int) (value & 0xFFFFFFFF)).toUpperCase(), 8, '0');
    }

    private static byte[] fromHexBinary(final String value) throws DecoderException {
        return Hex.decodeHex(value.toUpperCase().toCharArray());
    }

    private static String toHexBinary(final byte[] binary) {
        return new String(Hex.encodeHex(binary)).toUpperCase();
    }

    private static String toHexBinary(final byte[] binary, final int offset, final int length) {
        return new String(Hex.encodeHex(Arrays.copyOfRange(binary, offset, offset + length))).toUpperCase();
    }
    
    public static void main(final String[] args) throws Exception {
        // setup java logging
        System.setProperty( "java.util.logging.config.file", "logging.properties" );
        java.util.logging.LogManager.getLogManager().readConfiguration();
        // TODO change MYDEVICE below to match the ip address or hostname of your device
        final PhilipsAir philipsAir = new PhilipsAir("MYDEVICE", "JiangPan", System.out::println);
        philipsAir.initialize();
        // sleep to receive some status observations
        Thread.sleep(10000);
        /*
        You can send commands to the device with philipsAir.send() in the following format:

        {"state":{"desired":{"CommandType":"app","DeviceId":"DEVICEID","EnduserId":"USERID","CHANNEL":"STATE"}}}

        where
            DEVICEID is the DeviceId return from status observations
            USERID does not really make a difference, one could e.g. use "OpenHAB"
            CHANNEL is the channel whose state should be changed, e.g. "pwr" for power
            STATE is the state to change to, e.g. "0" to power off the device

        when the command failed the response is {"status":"failed"}
        when the command succeeded the response is {"status":"success"}
        */
        philipsAir.dispose();
    }
}