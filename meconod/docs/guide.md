
# Anti-Replay
## Anti-Replay Nonce
To protect against replay attacks, a counter value is stored for each node. If a node receives a message with an anti-replay nonce that is below the current minimum inbound anti-replay counter, the message will be dropped and ignored. Messages sent to a node will use the next unused anti replay counter value. Multiple attemps of sending a specific message should use the same anti-replay counter value.

# Messages
## Request/Response
Mecono uses a request/response method of messaging. This means that, for all messages, a response is requested. The content of the message payload is different depending on the purpose of the message, for example, a ping or arbitrary data.

## Payload Types
* **Ping Request** (type code `1`): A ping request on it's way to the destination. Usually sent to test a node that hasn't been contacted in a while, or to notify other nodes of the existence of this node.
* **Ping Response** (type code `2`): A response to a ping being sent back to the original ping request's origin.
* **Arbirary Data** (type code `3`): Completely arbitrary bytes as a payload on this message. Used by applications sending data via the network.
* **Route Request** (type code `4`): A request for route information to one or more nodes.
* **Route Response** (type code `5`): A response with zero or more routes to the nodes that were originally requested.

## Encoding and Encryption
```
Component          | Length | Cipher |
--------------------------------------
SCHEMA             | 4      | A      |
ITINERARY LENGTH   | 4      | A      |
ITINERARY          | Varies | A      |
MESSAGE KEY LENGTH | 4      | A      |
MESSAGE KEY        | Varies | AB     |
HEADER LENGTH      | 4      | A      |
HEADER             | Varies | AC     |
PAYLOAD LENGTH     | 4      | A      |
PAYLOAD            | Varies | AC     |
SIGNATURE LENGTH   | 4      |        |
SIGNATURE          |        |        |
```
* `A` indicates that the component is signed by the origin.
* `B` indicates that the component is asymmetrically encrypted with the destination's public key.
* `C` indicates that the component is symmetrically encrypted using the message encryption key.

### Public Information
The intinerary is public information because the network needs to know how to route the message. The signature of the non-signature parts of the message is also public, meaning that all nodes are able to ensure the validity of the message. The cipherbytes of each of the header and payload are also publicly visible.

### Itinerary
The itinerary component is simply a list of node public keys, indicating the route of the message from origin to destination. Because node public keys are fixed length, no separators or other length tracking in necessary to keep track of the start/stop of each public key.

### Maximum Message Size
Due to length field used to store several of the components, the payload, itinerary, or header may not exceed roughly 4,193,280 MB, which is nearly 4 GB. Other than the individual maximum lengths of components, there are no protocol-level restrictions on message size. However, node operators follow a general consensus that messages should not exceed a total of 4 MB, or message senders risk their message being dropped for being too large.