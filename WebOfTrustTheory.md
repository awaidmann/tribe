### Web of Trust

While the concept of a [Web of Trust (WoT)](https://en.wikipedia.org/wiki/Web_of_trust) is not a new idea (most notably [PGP](http://www.pgpi.org/doc/pgpintro/)), it is not as universally supported as the [Certificate Authority (CA)](https://en.wikipedia.org/wiki/Certificate_authority) trust model. The CA trust model was designed with a client-server architecture in mind, whereas WoT was designed for a secure distributed email system. It is easy to draw similarities between PGP's (the original WoT) and Warnable's needs. Both have users pushing data (email vs. fire alarm) to other users and both need to be fault tolerant/proactive against compromised users. In a CA model, a root authority signs all child keys and those keys may sign others, but if any key in the hierarchy is compromised then ALL of it's child keys must be considered compromised as well. In a WoT model, fault tolerance is achieved by having many different users sign a key. If any of the signing keys are compromised, then that record can be invalidated and the signed key can still be validated against any of the other signatures. [Here](https://www.linux.com/learn/pgp-web-trust-core-concepts-behind-trusted-communication) is a more detailed analysis on how PGP handles trust.

While [OpenSSL](https://www.openssl.org/) provides great command line tools to operate on keys and certificates, there are not mobile library equivalents for most of OpenSSL's functionality. However, Android and iOS do provide basic key pair generation, storage, signing, and verification libraries. These basic utilities are enough for us to build out a complete a WoT model, but not to create the more complicated [X.509 Certificates](https://en.wikipedia.org/wiki/X.509) needed for the CA model. Any CA implementation would require the user to request a valid certificate from a central server(s), which is just another point of failure and/or attack.

At the algorithm level, WoT trust resolution is no more than graph traversal. One difference between our traversal algorithm and most others is that we don't care about the shortest path only the first fully verified path between your key/node and any other. Our algorithm is informed by standard graph traversal algorithms like [Dijkstra](https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm) and [A*](https://en.wikipedia.org/wiki/A*_search_algorithm). One difference is that there is no obvious heuristic to weight different Trust Paths. Hence we have to search all available paths. Suggestions on how we can improve our search are listed in the [Reducing Traversal Time](#reducing_traversal_time) section.

This document will attempt to stay Warnable/Firebae agnostic when possible to keep it easy to maintain as the project changes. It is meant to be a general overview of our implementation and not a technical spec.

#### Axioms
  1. Private key of a key pair, is only stored on the user's device. Preferably, in a non-exportable form.

  2. A device only has one active private key at a time.

  3. If your stored public key matches your database public key record AND you can verify some chunk of data claimed to have been signed by you THEN you can trust that the chunk has not been tampered with.

  4. A link between two keys is valid if-and-only-if both keys have a verifiable [self-signature](#define_self_sig) and a verifiable signature from the other key, i.e. they were [mutually signed](#define_mutual).

#### Traversal
  1. Device receives data containing at least a signerID, a signingKeyID, a timestamp/lastModified date, and a [Base64](https://en.wikipedia.org/wiki/Base64) encoded [signature](#define_sign). We will refer to this key as the Target Key

  2. Fetch your key from device's key store NOT the database. Pull in any additional info you need to verify your [self-signature](#define_self_sig) and [Trust Record](#define_trust).

  3. Fetch Target Key info from database using provided signingKeyID. Verify the key's self-signature and Trust Record.

  4. Push your key and the Target Key (as [nodes](#define_node)) to the unsearched [Fringe](#define_fringe).

  5. For each node in the Fringe, attempt to establish a [bi-directional link](#define_bi_link) or [Trust Path](#define_trust_path) between your key/node and the Fringe key/node.

  6. If a link could be established, push your key's id to the end of the Trust Path and stash it on that node. If not, store nothing on that node.

  7. Repeat 5 and 6, but attempt to establish a link to the Target Key/Node instead of to your key/node.

  8. If any node satisfies both 6 and 7. Then terminate processing and return the Trust Paths to your key/node and the Target Key/Node. If not, continue.

  9. Remove all nodes currently in the Fringe.

  10. For all nodes from 9, iterate over their trust records and push all keys not previously in Fringe to the Fringe.

  11. Repeat 5-11 until a Trust Path is found which connects your key to the Target Key or until there are no more new keys to push into the Fringe.

  > NOTE: Any hits to the database could also include first hitting any locally stored key records. Local storage could potentially mitigate the effects of a DoS attack on the console/database.

#### Reducing Traversal Time

- <a id="reduce_cache">Intermediate Link Caching</a>

  Intermediate Link Caching (ILC) is a database side caching scheme allows users to save previously verified [Bi-Directional Links](#define_bi_link) to the key's [Trust Record](#define_trust) as one-way [Cached Links](#define_cache). In it's currently iteration, ILC only saves the keys which are part of the [Trust Path](#define_trust_path) for a given trust resolution between your key/node and a Target Key/Node. In a sense you are drawing a line across the trust graph and hoping future Trust Paths will intersect one or more of your saved paths. ILC is most effective when the resolution path contains a key with a large number of signatures (likely an admin). For each key/node in the Trust Path, an ILC Cached Link is created.

  The current implementation of ILC treats each cached link as a normal [Trusted Link](#define_trust_link) except that it is validated against the last element in it's ILC chain array. Because of this we can detect if the Target Key shares one of our ILC links before we validate every ILC chain link.

  Future enhancements, might make it capable to rebuild Trust Paths from a single ILC link. Or we could use server aided ILC, which would periodically map and cache paths through the graph. Users could then look up a given Trust Path without needing to manually traverse the graph every time.

  In theory, ILC could be expanded to include any keys which were successfully validated against your key or a key that you signed, or a key signed by a key that your signed, and so on. Because an unfinished Trust Path is not as likely to reach across the graph or go through a popular key/node and thus introduce unnecessary overhead and incur more database fetches.

- <a id="reduce_admin_sig">Admin Directed Signing</a>

  Admin Directed Signing (ADS) is an app level protection which only allows admins or building admins to initiate a [mutual signing](#define_mutual) event. In effect, this reduces the overall complexity of the trust graph by preventing the most abundant user type (normal user) from creating links between themselves. When resolving trust between two nodes the fewer paths we need to traverse/validate the faster we will find a solution. Without ADS or a similar graph pruning scheme scaling the trust resolution algorithm to communities or very large businesses will be difficult.

  The obvious drawbacks to this method are that it incurs more responsibility on the admins to ensure their whole school/office is properly signed and creates a number of points of failure (the admin devices) in the system. Ideally, devices/keys would only need to be resigned once a year, but that may change in practice.

  It is NOT currently implemented.

- <a id="reduce_admin_trav">Admin Directed Traversal</a>

  Admin Directed Traversal (ADT) is an algorithm level construct which can be used with [Admin Directed Signing](#reduce_admin_sig) to weight the links between keys/nodes rather than assuming that each key/node is equal. ADT would visit keys/nodes which are known to belong to admins or building admins before visiting keys/nodes belonging to average users. The theory is that due to the semi-structured nature of ADS, for any two keys/nodes in an organization they share some common supervisor who has either directly signed their keys or that of another supervisor.

  This is not the only weighting scheme possible, but it is the most straightforward given the current implementation of the app.

  It is NOT currently implemented.

#### Definitions

##### Key Object & Actions

- <a id="define_mutual">Mutual Signing</a>

  Mutual signing is the process where two user's reciprocally trust one another's keys and is the basis behind [Axiom 4](#axioms). It must be done in person to prevent spoofing attacks. The process requires each user has a device with the app installed and logged into a correctly configured account. An admin or building admin [initiates the exchange](#reduce_admin_sig) of public key info. The data can be conferred through different formats (QR code, WiFi Direct, Bluetooth, etc...), but any transfer method must, at a minimum, contain the key's id and the [Base64](https://en.wikipedia.org/wiki/Base64) encoded [self-signature](#define_self_sig) every device creates when it creates a new key pair. All other data may be fetched from the database. Each side performs this transfer. Once a user has received all the key info to verify, the device signs the data and pushes a new signature to the other user's key's [Signatures Record](#define_sig_record). Also, the signing user's key's [Trust Record](#define_trust) is updated, self signed, and pushed to the database to provide a convenient cache of trusted users/devices/keys. The process is complete once each side has successfully pushed the newly signed data to the database.

- <a id="define_self_sig">Self Signature</a>

  Every time a new public/private key pair are created, it is necessary to [sign](#define_sign), with the new private key, the new PEM encoded public key, expiration date, the key's id, the owner's id, signing key (our key), and signer's id (us). This ensures that a key is able to self [validate](#define_verify) and that any of those fields have not been tampered with. Technically, a self-signature is a [Trusted Link](#define_trust_link) to itself, meaning it has both a [Trust Record](#define_trust) and a [Signatures Record](#define_sig_record) for itself.

- <a id="define_sig_record">Signatures Record</a>

  The list of signatures and associated information about the signer and signing key. Each signature entry is individually created by the signer, signed by the signer's private key, and pushed to the signed key's Signatures Record. Essentially, by signing another's key you are vouching for that user/key pair to the rest of the organization. An entry in the Signatures Record corresponds to the inbound half of a [Trusted Link](#define_trust_link) for every key which has signed the enclosing key (including itself).

- <a id="define_trust">Trust Record</a>

  The Trust Record is the inverse of the [Signature Record](#define_sig_record). The Trust Record is stored in a key's record and contains outbound half of a [Trusted Link](#define_trust_link) for every key the enclosing key has signed (including itself). The entire Trust Record is signed by the enclosing key's associated private key.


##### Signing/Verification
- <a id="define_ecc">Elliptic Curve Cryptography</a>

  [Elliptic Curve Cryptography (ECC)](http://arstechnica.com/security/2013/10/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/) is becoming the new best practice for [asymmetric cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography) schemes. It is attempting to replace [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) as ECC's key sizes are substantially smaller, but can guarantee the equivalent protection as an RSA key of a much larger size.

  The current version of the app uses the prime256v1(secp256r1) curve as it is the most universally supported curve.

- <a id="define_sign">Sign</a>

  To sign data, we compute the [SHA-1 hash](https://en.wikipedia.org/wiki/SHA-1) of a object, by first serializing it into a bit stream then feeding it into the SHA-1 hash function. We pass this hash and the private key component of an [Elliptic Curve Key Pair](#define_ecc) to the [Elliptic Curve Digital Signing Algorithm's (ECDSA)](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) signing function. Typically, the computed signature is then saved alongside it's corresponding data so that it may be independently [verified](#define_verify) by other devices. All signatures must be stored as a [Base64](https://en.wikipedia.org/wiki/Base64) string, as it is more space efficient than the Hex equivalent.

  The current version of the app does not use any padding for the SHA-1 hash.

- <a id="define_verify">Verify</a>

  A [signature](#define_sign) can be verified against a chunk of data by feeding the signature, signer's corresponding public key, and a serialized version of the to-be-verified data into the [Elliptic Curve Digital Signing Algorithm's (ECDSA)](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) verification function. Ensure that the you use the same hashing algorithm parameter (we use [SHA-1](https://en.wikipedia.org/wiki/SHA-1)) for the signing and verification steps.

##### Trust Resolution (Alg. Constructs)

- <a id="define_bi_link">Bi-Directional Link</a>

  A Bi-Directional Link can be thought of as two [verified](#define_verify) [Trusted Links](#define_trust_link) going in opposite directions (i.e. Key A trusts Key B and Key B trust Key A). If a compromised device/account begins claiming they trust dozens of keys, the [traversal](#traversal) still won't consider the link valid if there is not an inverse record pointing to the compromised key. Bi-Directional Links' validity is determined on a key-to-key basis and the invalid pair {Key A, Key B} does not necessarily invalidate pairs {Key A, Key C} and {Key B, Key C}.

- <a id="define_cache">Cached Link</a>

  A Cached Link is a specific type of [Trusted Link](#define_trust_link) which represents a particular key/node in a previously computed [Trust Path](#define_trust_path). Each Cached Link entry contains the same data in a Trusted Link, plus a chain of other key ids which lead from that key entry to the enclosing key. All cached links have a [Trust Level](#define_trust_level) greater than 1, meaning that there is at least 1 other key/node between the enclosing key and the Cached Link's key.

  For example, suppose we attempted to compute the Trust Path between ourself (OurKey) and Key C. Then assume that the path we computed resulted in the path OurKey -> Key A -> Key B -> Key C. What we can determine from this path that OurKey and Key A are [mutually signed](#define_mutual), Key A and Key B are mutually signed, and so are Key B and Key C. OurKey then stashes this path on the database by adding three entries to the Trust Record. One for Key A with a Trust Level of 1 and a chain containing [OurKey], one for Key B with a Trust Level of 2 and a chain containing [OurKey, Key A], and finally an entry for Key C with a Trust Level of 3 and a chain containing [OurKey, Key A, Key B].

- <a id="define_fringe">Fringe</a>

  The Fringe is a computational object that represents all known keys that have not already been fetched from the database. The Fringe doesn't technically have to be a single data structure. Each phase of fetching, [verification](#define_verify), resolution, etc... may have their own Fringe structure if you want all those behaviors to run separately/in parallel.

- <a id="define_node">Node</a>

  A Node is a computational object that represents a single key in the [Trust Graph](#define_trust_graph). How a system stores and populates Nodes is implementation dependent. Technically, all trust resolution (Trust Graph [traversal](#traversal)) functions are executed on Node objects.

- <a id="define_trust_graph">Trust Graph</a>

   A Trust Graph consists of a network of all known and [verified](#define_verify) [Trusted Links](#define_trust_link) between a set of keys. Remember, that we begin computing the Trust Graph at two points, our key/node and the target key/node. Our goal is to hopefully connect the two separate Trust Graph into a single network and compute a [Trust Path](#define_trust_path) between our key/node and the target key/node. If the two Trust Graphs cannot be connected then we must assume no valid Trust Path exists and the data signed by the target key is unverifiable.

   Our current algorithm has no bound on the size of the Trust Graph, but it can guarantee a key is fetched only once and that a key only needs to look 1 level deep (it's signer nodes) to find a route to the two root nodes. As long as you have a properly shared single source of visited keys/nodes, the building out of the Trust Graph can be highly parallelized.  

- <a id="define_trust_level">Trust Level</a>

  While inspired by PGP's concept of [Trusted/Meta-Introducers](https://www.linux.com/blog/pgp-web-trust-delegated-trust-and-keyservers), our definition of Trust Level deviates from the PGP definition. For us, Trust Level is simply a measurement of how far away, in the [Trust Graph](#define_trust_graph), a [Trusted Link's](#define_trust_link) key is from the enclosing key. A Trust Level of 0 indicates your key and can be trusted completely. A Trust Level of 1 is that of any key your key has [mutually signed](#define_mutual) and indicates a real world trust relationship between you and another user. A Trust Level greater than 1 indicates an unbroken chain of trusted/verifiable keys between yourself and the trusted key.

- <a id="define_trust_path">Trust Path</a>

  A Trust Path is any unbroken chain of [Bi-Directional Links](#define_bi_link) between two distant keys in the [Trust Graph](#define_trust_graph). Typically we are trying to connect the Trust Paths rooted at our key and some target key into a single Trust Path. If a Trust Path can be computed between any two keys/nodes then those two users can confidently communicate with one another despite not trusting (or even knowing) the other one.

- <a id="define_trust_link">Trusted Link</a>

  A Trusted Link consists of two parts. The first part is an outbound entry in the [Trust Record](#define_trust) consisting of the trusted key's id, trusted key owner's id, and a timestamp. The second is an inbound entry in the trusted key's [Signatures Record](#define_sig_record) consisting of the trusted key's id, trusted key owner's id, the signer's id (our id), the signer's key's id, a timestamp, and a [signature](#define_sign) (using your private key, of course) of all the previous data plus the trusted key's PEM encoded public key. Our entire Trust Record is resigned every time an entry is created or modified. A Trusted Link cannot be considered valid (or trusted) if both inbound and outbound entries' signatures cannot be [verified](#define_verify).
