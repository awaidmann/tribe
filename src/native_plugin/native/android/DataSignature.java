package com.warnable.plugin;

import org.json.JSONException;
import org.json.JSONObject;

import android.util.Base64;
import android.util.Log;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Iterator;
import java.text.DecimalFormat;
import java.math.RoundingMode;

public class DataSignature {
    private static final String CHAR_SET = "UTF-16BE";
    private static final String SIG_ALG = "SHA1withECDSA";

    private static final String SIG_PROP = "sig";
    private static final String LAST_MODIFIED_PROP = "lastModified";
    private static final String SIGNER_PROP = "signerID";
    private static final String KEY_PROP = "signingKeyID";

    public static JSONObject sign(JSONObject data, String signingKeyID, String signerID, long lastModified) throws Exception {
        data.put(LAST_MODIFIED_PROP, lastModified);
        data.put(SIGNER_PROP, signerID);
        data.put(KEY_PROP, signingKeyID);

        String sig = sign(signerID, buildSigStream(data));
        if (sig != null && sig.length() > 0) {
          data.put(SIG_PROP, sig);
          return data;
        } else {
          return null;
        }
    }

    private static String sign(String signerID, byte[] stream) throws Exception {
        PrivateKey pk = KeyManager.getPrivateKey(signerID);
        if (pk != null) {
            Signature sig = Signature.getInstance(SIG_ALG);
            sig.initSign(pk);
            sig.update(stream);
            return Base64.encodeToString(sig.sign(), Base64.DEFAULT);
        } else {
          return null;
        }
    }

    public static boolean verify(JSONObject data, String signerPK, String signerID) throws Exception {
        return verify(data, KeyManager.publicKeyFromString(signerPK, signerID));
    }

    private static boolean verify(JSONObject data, PublicKey signerPK) throws Exception {
        String signature = (String)data.remove(SIG_PROP);
        byte[] sigBytes = Base64.decode(signature, Base64.DEFAULT);
        if (sigBytes != null && sigBytes.length > 0) {
            Signature sig = Signature.getInstance(SIG_ALG);
            sig.initVerify(signerPK);
            sig.update(buildSigStream(data));
            return sig.verify(sigBytes);
        }
        return false;
    }

    /*
      All returned types (except objects) are extracted as strings. This way we don't
      have to worry about internal representations of numbers (doubles vs ints) across
      platforms. JSON arrays are not considered here because Firebase has no concept
      of array even if JSON does.

      The keys are then sorted alphabetically to ensure a common serializable specification
      across platforms.

      For every key and value, append 4 NULL(0x0) bytes to the end of it's byte array.
      Nested objects are recursively converted to byte arrays and treated as a if it
      was a single string value. What this means is that you can roughly detect the
      end of a nested object as 2 or more sets of 4 NULLs, depending on the depth.

      The padding scheme was chosen to ensure uniqueness across objects. There is a
      possiblity that a simple byte concatenation without padding could result in a
      collision between objects. For example:

      obj1 = { "a": { "b": 1}}
      obj2 = { "a": "b1" }
      w/o padding:
      obj1 = 0061 0062 0031
      obj2 = 0061 0062 0031

      w/ padding:
      obj1 = 0061 0000 0000 0062 0000 0000 0031 0000 0000 0000 0000
      obj2 = 0061 0000 0000 0062 0031 0000 0000

      The NULL padding was added because the JSON specification does not allow for
      control characters to be sent. Even if a control character is escaped (\0,
      \n, etc..) it will be represented as the literal characters "\" and "0" and not
      it's actual value.
    */
    private static byte[] buildSigStream(JSONObject data) throws Exception {
        //https://en.wikipedia.org/wiki/Decimal_degrees
        DecimalFormat decFormat = new DecimalFormat("#.########");
        decFormat.setRoundingMode(RoundingMode.HALF_UP);

        Iterator<String> props = data.keys();
        String[] orderedProps = new String[data.length()];

        int index = 0;
        while(props.hasNext()) {
            orderedProps[index] = props.next();
            index++;
        }

        Arrays.sort(orderedProps);

        index = 0;
        byte[][] acc = new byte[orderedProps.length][];
        for(String prop : orderedProps) {
            byte[] valStream;
            Object value = data.get(prop);
            if (value instanceof Double) {
              valStream = decFormat.format((Double)value).getBytes(CHAR_SET);
            } else if (value instanceof JSONObject) {
              valStream = buildSigStream((JSONObject)value);
            } else {
              valStream = String.valueOf(value).getBytes(CHAR_SET);
            }
            byte[] propStream = prop.getBytes(CHAR_SET);
            byte[] delim = {0, 0, 0, 0};
            byte[] temp = new byte[propStream.length + valStream.length + 2*delim.length];

            System.arraycopy(propStream, 0, temp, 0, propStream.length);
            System.arraycopy(delim, 0, temp, propStream.length, delim.length);
            System.arraycopy(valStream, 0, temp, propStream.length + delim.length, valStream.length);
            System.arraycopy(delim, 0, temp, propStream.length + delim.length + valStream.length, delim.length);

            acc[index] = temp;
            index++;
        }

        int length = 0;
        for(byte[] stream : acc) {
            length += stream.length;
        }

        byte[] serial = new byte[length];
        index = 0;
        for(byte[] stream : acc) {
            System.arraycopy(stream, 0, serial, index, stream.length);
            index += stream.length;
        }

        return serial;
    }
}
