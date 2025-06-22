# Double Ratchet

Forward secrecy: The **double-rachet (send-receive pair)** secures against attackers reading [**backwards**] if the event within the session is hijacked (if state is leaked) to deduce **past states** both if the present shared secret key of the root ratchet is leaked.

#![ratchet_turn_ratchet](https://github.com/ursa-mikail/mechanisms/blob/main/security/double_ratchet/ratchet_turn_ratchet.svg)

<img src="https://github.com/ursa-mikail/mechanisms/blob/main/security/double_ratchet/ratchet_turn_ratchet.svg" alt="ratchet_turn_ratchet">

![ratchet_symmetric](https://github.com/ursa-mikail/mechanisms/blob/main/security/double_ratchet/ratchet_symmetric.svg)

Post-compromise: The **Diffie-Hellman ratchet** to reset the session secures against attackers reading [**forwards**] if the event within the session is hijacked (if state is leaked) to deduce **future states** both if the present shared secret key of the root ratchet is leaked. 

![ratchet_dh](https://github.com/ursa-mikail/mechanisms/blob/main/security/double_ratchet/ratchet_dh.svg)