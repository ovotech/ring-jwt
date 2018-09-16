(ns ring.middleware.jwk
  (:import (java.net URL)
           (com.auth0.jwk UrlJwkProvider Jwk)))

(defn ^Jwk get-jwk
  "Pulls the specified key as a JWK from the specified URL."
  [url key-id]
  (-> (URL. url)
      (UrlJwkProvider.)
      (.get key-id)
      (.getPublicKey)))