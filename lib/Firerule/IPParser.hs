{-# LANGUAGE FlexibleContexts #-}
module Firerule.IPParser where

import qualified Data.Char as Char
import qualified Text.Parsec as Parsec
import qualified Data.Functor.Identity as Identity
import Text.Parsec((<|>))

integer :: (Parsec.Stream s Identity.Identity Char,
    Read v, Bounded v, Ord v) => Parsec.Parsec s u v
integer = do
    s <- Parsec.many1 Parsec.digit
    case reads s of
      [(v, "")] ->
          if v >= minBound && v <= maxBound
             then return v
             else fail "integer is out of bounds"
      _ -> fail "not a integer"

boundedInteger min max = do
    v <- integer
    if v >= min && v <= max
       then return v
       else fail "integer is out of bounds"

hexInteger :: (Parsec.Stream s Identity.Identity Char, Num v) =>
    Parsec.Parsec s u v
hexInteger = do
    s <- Parsec.many1 (Parsec.digit <|> Parsec.hexDigit)
    return $ foldl (\r v -> r*16 + v) 0 $
        map (fromIntegral . Char.digitToInt) s

optionalHexInteger :: (Parsec.Stream s Identity.Identity Char, Num v) =>
    Parsec.Parsec s u (Maybe v)
optionalHexInteger = Parsec.option Nothing (fmap Just hexInteger)
