#### TODO
* refactor everything into a proper class
* better prime number generation
* implement the following:
  * Setting: the alphabet will have 27 characters, the blank and the 26 letters of the English alphabet.
  * Generates a public key and a private key. The public key will be randomly generated in the required interval.
	* Plaintext message units are blocks of k letters, whereas ciphertext message units are blocks of l letters. The plaintext is completed with blanks, when necessary.
	  * We must have 27<sup>k</sup> < n < 27<sup>l</sup>
  * Using the public key, encrypts a given plaintext. 
    * there will be a plaintext validation - check that all characters of initial message belong to the alphabet
  * Using the private key, decrypts a given ciphertext. 
    * there will be a ciphertext validation - ?
