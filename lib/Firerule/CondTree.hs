module Firerule.CondTree(CondTree(..), size, showTree, foldLeft, eqToDepth) where

import qualified Data.Tree as Tree

data CondTree a = Leaf a |
    NodeOr (CondTree a) (CondTree a) |
    NodeAnd (CondTree a) (CondTree a) |
    NodeNot (CondTree a) |
    NodeTrue | NodeFalse

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
    traverse f (NodeOr left right) = NodeOr <$> (traverse f left) <*>
        (traverse f right)
    traverse f (NodeAnd left right) = NodeAnd <$> (traverse f left) <*>
        (traverse f right)
    traverse f (NodeNot node) = NodeNot <$> traverse f node
    traverse _ NodeTrue = pure NodeTrue
    traverse _ NodeFalse = pure NodeFalse

instance Eq a => Eq (CondTree a) where
    (==) = twofoldLeft cmp True
        where cmp r (Just (left, right)) = r && (left == right)
              cmp _ Nothing = False

instance Show a => Show (CondTree a) where
    show = showTree

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

eqToDepth d _ _ | d <= 0 = True
eqToDepth d (Leaf left) (Leaf right) = left == right
eqToDepth d (NodeAnd aLeft aRight) (NodeAnd bLeft bRight) =
    eqToDepth (d-1) aLeft bLeft && eqToDepth (d-1) aRight bRight
eqToDepth d (NodeOr aLeft aRight) (NodeOr bLeft bRight) =
    eqToDepth (d-1) aLeft bLeft && eqToDepth (d-1) aRight bRight
eqToDepth d (NodeNot left) (NodeNot right) = eqToDepth (d-1) left right
eqToDepth d NodeTrue NodeTrue = True
eqToDepth d NodeFalse NodeFalse = True
eqToDepth _ _ _ = False

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
