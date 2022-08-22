# What is it
JavaScript implementation of the <a target="_blank" href="https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.117.7149&rep=rep1&type=pdf">Feige-Fiat-Shamir identification scheme</a> - an elegant, practical interactive zero knowledge proof of knowledge.

Usage example:


```javascript
const { BigIntegerGenerator, Ffs, jsbn } = require("feige_fiat_shamir");

const randomInt = function(max, min=0) {
  return Math.floor(Math.random() * (max - min)) + min;
};
const ffsParameters = function(pqBytes, siBytes, k) {
  const seedBytesCount = randomInt(128, 3);
  const rand = new BigIntegerGenerator([randomInt(255), randomInt(255), randomInt(255), randomInt(255), randomInt(255)], seedBytesCount);
  const seedBytesArray = rand.nextAsBytes();
  return {seedBytesArray: seedBytesArray, pqBytes: pqBytes, siBytes: siBytes, k: k};
};


/*
  For the values below, see the Feige-Fiat-Shamir paper
  https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.117.7149&rep=rep1&type=pdf

  Or as of 2022/08/21, Wikipedia followed the same definitions:
  https://en.wikipedia.org/wiki/Feige%E2%80%93Fiat%E2%80%93Shamir_identification_scheme
*/
/*
  p and q are 2 primes; this sets the number of bytes in each.
*/
const pqBytes = 128;
/*
  Si are secret numbers coprime to n=pq; this sets the number of bytes per number
*/
const siBytes = 128;
/*
  k is the number of Si values
*/
const k = 64;
const { seedBytesArray } = ffsParameters(pqBytes, siBytes, k);
const ffs = new Ffs(seedBytesArray, pqBytes, siBytes, k);

const [n, S, V] = ffs.setup();
const [sign, r, x] = ffs.initProof(n);
const A = ffs.chooseA();
const y = ffs.computeY(r, S, A, n);

const shouldBeCorrect = ffs.checkY(y, n, x, A, V);

/* Corrupt Y and see that the FFS proof fails */
const wrongY = y.subtract(jsbn.BigInteger.ONE);
const shouldBeIncorrect = ffs.checkY(wrongY, n, x, A, V);
```

# License
Licensed under MIT - feel free to use commercially.

Attribution should go to Aleksei Chernikov, https://alexey-dc.com