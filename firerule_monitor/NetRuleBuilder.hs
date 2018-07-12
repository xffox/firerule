module NetRuleBuilder where

import qualified Data.List as List
import qualified Text.Printf as Printf
import qualified System.IO as SIO
import qualified Control.Monad.Trans.Except as Except
import qualified Control.Monad.Trans.Class as Trans
import qualified Control.DeepSeq as DeepSeq
import qualified Control.Exception as Exception

import qualified Firerule.Format.RuleParser as RuleParser
import qualified Firerule.Format.PrefixTree as PrefixTree
import qualified Firerule.Format.ConfBuilder as ConfBuilder
import qualified NetRule as NetRule

readNetRule :: String -> Except.ExceptT String IO NetRule.NetRule
readNetRule path = do
    inp <- Trans.lift $
        Exception.catch
            (SIO.withFile path SIO.ReadMode $ \h -> do
                inp <- SIO.hGetContents h
                Exception.evaluate $ DeepSeq.rnf inp
                return inp)
            (\e -> do
                let err = show (e :: Exception.IOException)
                fail $ Printf.printf
                    "failed to read net rule file: %s: '%s'" err path)
    buildNetRule inp

buildNetRule fr = do
    (RuleParser.Firewall rs) <- liftEither $ RuleParser.parseFirewall fr
    case rs of
      [RuleParser.Rule "network" jumps] -> do
          let (defaultJumps, actJumps) = List.partition isDefaultJump jumps
          case defaultJumps of
            [RuleParser.DefaultJump act] -> NetRule.NetRule <$>
                ((,) <$> (pure act) <*> (buildFirewall act)) <*>
                    mapM buildJump actJumps
      _ -> fail "invalid net rule: should be \"network\" only"

buildConnectionNameCondition [connection] = return $
    NetRule.ConnectionName connection
buildConnectionNameCondition _ = fail "invalid network condition arguments"

buildJump (RuleParser.Jump act tr) =
    (,) <$> ((,) <$> (pure act) <*> (buildFirewall act)) <*>
        mapM buildCondition tr
buildJump _ = fail "invalid jump"

buildFirewall path = do
    inp <- Trans.lift $
        Exception.catch
            (SIO.withFile path SIO.ReadMode $ \h -> do
                    inp <- SIO.hGetContents h
                    Exception.evaluate $ DeepSeq.rnf inp
                    return inp)
            (\e -> do
                let err = show (e :: Exception.IOException)
                fail $ Printf.printf
                        "failed to read firewall file: %s: '%s'" err path)
    liftEither $ RuleParser.parseFirewall inp >>= ConfBuilder.buildConf

buildCondition (RuleParser.Condition as@(ns:args)) = do
    ns' <- liftEither $ RuleParser.parseNamespace ns
    case PrefixTree.findPrefix ns' conditions of
      Just b -> b args
      _ -> fail $ Printf.printf "condition not found: %s" (show as)
buildCondition _ = fail "invalid condition clause"

isDefaultJump (RuleParser.DefaultJump _) = True
isDefaultJump _ = False

liftEither (Left err) = fail err
liftEither (Right val) = return val

conditions = PrefixTree.buildPrefixTree $
    PrefixTree.appendPrefix ["connection", "name"]
        buildConnectionNameCondition
