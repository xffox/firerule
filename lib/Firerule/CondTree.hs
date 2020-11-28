module Firerule.CondTree(CondTree(..), CutCondTree(..),
    size, showTree, foldLeft, restructTreeM) where

import qualified Data.Maybe as Maybe
import qualified Data.Tree as Tree

data CondTree a = Leaf a |
    NodeOr (CondTree a) (CondTree a) |
    NodeAnd (CondTree a) (CondTree a) |
    NodeNot (CondTree a) |
    NodeTrue | NodeFalse
    deriving (Eq, Ord)

instance Functor CondTree where
    fmap f (Leaf v) = Leaf $ f v
    fmap f (NodeOr left right) = NodeOr (fmap f left) (fmap f right)
    fmap f (NodeAnd left right) = NodeAnd (fmap f left) (fmap f right)
    fmap f (NodeNot node) = NodeNot $ fmap f node
    fmap _ NodeTrue = NodeTrue
    fmap _ NodeFalse = NodeFalse

instance Foldable CondTree where
    foldr f z (Leaf v) = f v z
    foldr f z (NodeOr left right) = foldr f (foldr f z right) left
    foldr f z (NodeAnd left right) = foldr f (foldr f z right) left
    foldr f z (NodeNot node) = foldr f z node
    foldr _ z NodeTrue = z
    foldr _ z NodeFalse = z

instance Traversable CondTree where
    traverse f (Leaf v) = Leaf <$> f v
    traverse f (NodeOr left right) = NodeOr <$> traverse f left <*>
        traverse f right
    traverse f (NodeAnd left right) = NodeAnd <$> traverse f left <*>
        traverse f right
    traverse f (NodeNot node) = NodeNot <$> traverse f node
    traverse _ NodeTrue = pure NodeTrue
    traverse _ NodeFalse = pure NodeFalse

instance Show a => Show (CondTree a) where
    show = showTree

data CutCondTree a = CutCondTree Int (CondTree a)

instance Eq a => Eq (CutCondTree a) where
    (==) (CutCondTree d1 tr1) (CutCondTree d2 tr2) =
        d1 == d2 && eqToDepth d1 tr1 tr2

instance Ord a => Ord (CutCondTree a) where
    compare (CutCondTree d1 tr1) (CutCondTree d2 tr2) =
        case compare d1 d2 of
          EQ -> ordToDepth d1 tr1 tr2
          r -> r

eqToDepth d _ _ | d <= 0 = True
eqToDepth d (NodeAnd aLeft aRight) (NodeAnd bLeft bRight) =
    eqToDepth (d-1) aLeft bLeft && eqToDepth (d-1) aRight bRight
eqToDepth d (NodeOr aLeft aRight) (NodeOr bLeft bRight) =
    eqToDepth (d-1) aLeft bLeft && eqToDepth (d-1) aRight bRight
eqToDepth d (NodeNot left) (NodeNot right) = eqToDepth (d-1) left right
eqToDepth _ n1 n2 = n1 == n2

ordToDepth d _ _ | d <= 0 = EQ
ordToDepth d (NodeAnd left1 right1) (NodeAnd left2 right2) =
    case ordToDepth (d-1) left1 left2 of
      EQ -> ordToDepth (d-1) right1 right2
      r -> r
ordToDepth d (NodeOr left1 right1) (NodeOr left2 right2) =
    case ordToDepth (d-1) left1 left2 of
      EQ -> ordToDepth (d-1) right1 right2
      r -> r
ordToDepth d (NodeNot n1) (NodeNot n2) = ordToDepth (d-1) n1 n2
ordToDepth _ n1 n2 = compare n1 n2

restructTreeM :: Monad m => (CondTree a -> m (CondTree a)) ->
    CondTree a -> m (CondTree a)
restructTreeM f n = restructTreeM' n >>= f
    where restructTreeM' (NodeNot n) =
              NodeNot <$> restructTreeM f n
          restructTreeM' (NodeOr left right) =
              NodeOr <$> restructTreeM f left <*> restructTreeM f right
          restructTreeM' (NodeAnd left right) =
              NodeAnd <$> restructTreeM f left <*> restructTreeM f right
          restructTreeM' n = return n

size = foldLeft (\r _ -> r + 1) 0

showTree tr = Tree.drawTree $ toTree tr
    where toTree (Leaf v) = Tree.Node (show v) []
          toTree (NodeAnd left right) =
              Tree.Node "<and>" [toTree left, toTree right]
          toTree (NodeOr left right) =
              Tree.Node "<or>" [toTree left, toTree right]
          toTree (NodeNot node) = Tree.Node "<not>" [toTree node]
          toTree NodeTrue = Tree.Node "<true>" []
          toTree NodeFalse = Tree.Node "<false>" []

foldLeft f r = foldLeft' r id
    where
        foldLeft' v cnt n@(NodeAnd left right) =
            foldLeft' v (\p -> foldLeft' (f p n) cnt right) left
        foldLeft' v cnt n@(NodeOr left right) =
            foldLeft' v (\p -> foldLeft' (f p n) cnt right) left
        foldLeft' v cnt n@(NodeNot node) =
            foldLeft' v (\p -> cnt $ f p n) node
        foldLeft' v cnt n = cnt $ f v n

twofoldLeft f r = twofoldLeft' r id
    where
        twofoldLeft' v cnt (Leaf a) (Leaf b) = cnt $ f v $ Just (a, b)
        twofoldLeft' v cnt (NodeAnd aLeft aRight) (NodeAnd bLeft bRight) =
            twofoldLeft' v (\p -> twofoldLeft' p cnt aLeft bLeft) aRight bRight
        twofoldLeft' v cnt (NodeOr aLeft aRight) (NodeOr bLeft bRight) =
            twofoldLeft' v (\p -> twofoldLeft' p cnt aLeft bLeft) aRight aRight
        twofoldLeft' v cnt (NodeNot aNode) (NodeNot bNode) =
            twofoldLeft' v cnt aNode bNode
        twofoldLeft' v cnt NodeTrue NodeTrue = cnt v
        twofoldLeft' v cnt NodeFalse NodeFalse = cnt v
        twofoldLeft' v cnt _ _ = cnt $ f v Nothing
