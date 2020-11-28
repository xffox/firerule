{-# LANGUAGE TupleSections #-}
{-# LANGUAGE FlexibleInstances #-}
module Firerule.BoolPair(BoolPair(..), negatePair) where

import Control.Applicative((<|>))

import qualified Firerule.ValueSet as VS
import qualified Firerule.Wrapped as Wrapped

type BoolPair a = (Bool, a)

negatePair (b, v) = (not b, v)

instance VS.Mergeable e => VS.Mergeable (Bool, e) where
    intersection (negLeft, left) (negRight, right)
      | negLeft == negRight = Wrapped.mapSimpleValue (negLeft,) $
          VS.intersection left right
    intersection left@(False, _) right@(True, _) =
        VS.intersection right left
    intersection (True, left) (False, right)
      | VS.isSubset left right = VS.fromCategory VS.EmptySet
    intersection _ _ = VS.fromCategory VS.SomeSet
    union (negLeft, left) (negRight, right)
      | negLeft == negRight = Wrapped.mapSimpleValue (negLeft,) $
          VS.union left right
      | (negLeft || negRight) &&
          not (negLeft && negRight) &&
              (VS.category (VS.intersection left right) /= VS.EmptySet) =
                  VS.fromCategory VS.UniverseSet
      | otherwise = VS.fromCategory VS.SomeSet
    emptySet = fmap (True,) VS.emptySet <|> fmap (False,) VS.universeSet
    universeSet = fmap (True,) VS.universeSet <|> fmap (False,) VS.emptySet
    isEmptySet (True, v) = VS.isEmptySet v
    isEmptySet (False, v) = VS.isUniverseSet v
    isUniverseSet (True, v) = VS.isUniverseSet v
    isUniverseSet (False, v) = VS.isEmptySet v
