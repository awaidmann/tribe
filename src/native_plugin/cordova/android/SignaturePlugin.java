package com.tribe.plugin;

import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;

import android.util.Base64;
import android.content.Context;
import java.security.PublicKey;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class SignaturePlugin extends CordovaPlugin {
  private static String INVALID_PARAMS_MSG = "Invalid parameter list";
  public Context context;

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
      super.initialize(cordova, webView);
      context = cordova.getActivity();
  }

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    try {
      if (action.equals("sign")) {
        if (args.length() == 4) {
          JSONObject data = args.getJSONObject(0);
          String signingKeyID = args.getString(1);
          String signerID = args.getString(2);
          long lastModified = args.getLong(3);

          JSONObject dataWithSig = DataSignature.sign(data, signingKeyID, signerID, lastModified);
          if (dataWithSig != null) {
            callbackContext.success(dataWithSig);
          } else {
            callbackContext.error("Signature creation failed");
          }
        } else {
          callbackContext.error(INVALID_PARAMS_MSG);
        }

      } else if (action.equals("verify")) {
        if (args.length() == 3) {
          JSONObject dataWithSig = args.getJSONObject(0);
          String pkStr = args.getString(1);
          String signerID = args.getString(2);

          boolean isVerified = DataSignature.verify(dataWithSig, pkStr, signerID);
          if (isVerified) {
            callbackContext.success();
          } else {
            callbackContext.error("Verification failed");
          }
        } else {
          callbackContext.error(INVALID_PARAMS_MSG);
        }

      } else if (action.equals("genKeyPairIfNecessary")) {
        if (args.length() == 1) {
          String uid = args.getString(0);

          int wasCreated = KeyManager.generateKeyPairIfNecessary(context, uid);
          if (wasCreated == KeyManager.KEY_PAIR_GENERATED) {
            callbackContext.success(1);
          } else if (wasCreated == KeyManager.KEY_PAIR_VALID) {
            callbackContext.success(0);
          } else {
            callbackContext.error("Key pair creation failed");
          }
        } else {
          callbackContext.error(INVALID_PARAMS_MSG);
        }

      } else if (action.equals("getPublicKey")) {
        if (args.length() == 1) {
          String uid = args.getString(0);

          String pk = KeyManager.getPEMPublicKey(uid);
          if (pk != null) {
            callbackContext.success(pk);
          } else {
            callbackContext.error("Could not fetch public key for " + uid);
          }
        } else {
          callbackContext.error(INVALID_PARAMS_MSG);
        }

      } else {
        return false;
      }

    } catch (Exception e) {
      callbackContext.error(e.getMessage());
    }

    return true;
  }
}
