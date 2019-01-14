(ns ring.middleware.jwk
  (:import (java.net URL)
           (com.auth0.jwk GuavaCachedJwkProvider UrlJwkProvider Jwk)
           (com.auth0.jwt.interfaces RSAKeyProvider)))

(defn ^RSAKeyProvider jwk-provider
  "Creates a provider that gets the public keys for tokens"
  [url]
  (let [jwk-provider (-> (URL. url)
                         (UrlJwkProvider.)
                         (GuavaCachedJwkProvider.))]
    (reify RSAKeyProvider
      (getPublicKeyById [_, key-id]
        (-> (.get jwk-provider key-id)
            (.getPublicKey)))
      (getPrivateKey [_] nil)
      (getPrivateKeyId [_] nil))))

(defn ^RSAKeyProvider simple-jwk-provider
  "Creates a provider that gets a public key from the kid attribut by calling a user provided fn"
  [key-fn]
  (reify RSAKeyProvider
    (getPublicKeyById [_, key-id]
      (key-fn key-id)
      )
    (getPrivateKey [_] nil)
    (getPrivateKeyId [_] nil)
    )
  )
