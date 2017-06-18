module Crypto.Ciphering.Stream
    ( cipherVernam
    , uncipherVernam
    , cipherECB
    , uncipherECB
    , cipherCBC
    , uncipherCBC
    ) where

import Data.Bits

-- | Vernam cipher / One-time pad
-- prop> length xs <= length ks ==> xs == uncipherVernam ks (cipherVernam ks xs)
cipherVernam :: (Num a, Bits a) => [a] -> [a] -> [a]
cipherVernam k c = zipWith xor c k

uncipherVernam :: (Num a, Bits a) => [a] -> [a] -> [a]
uncipherVernam k c = zipWith xor c k

-- | Electronic Codebook (ECB)
-- prop> xs == uncipherECB (xor x) (cipherECB (xor x) xs)
cipherECB :: Bits a => (a -> a) -> [a] -> [a]
cipherECB f c = map f c

uncipherECB :: Bits a => (a -> a) -> [a] -> [a]
uncipherECB f c = map f c

-- | Cipher Block Chaining (CBC)
-- prop> xs == uncipherCBC iv (xor x) (cipherCBC iv (xor x) xs)
cipherCBC :: Bits a => a -> (a -> a) -> [a] -> [a]
cipherCBC iv f c = tail (scanl (\prev cur -> f (xor prev cur)) iv c)

uncipherCBC :: Bits a => a -> (a -> a) -> [a] -> [a]
uncipherCBC iv f c = zipWith (\prev curr -> xor prev (f curr)) (iv:c) c
