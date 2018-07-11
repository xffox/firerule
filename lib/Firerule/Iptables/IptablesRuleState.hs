module Firerule.Iptables.IptablesRuleState
    (IptablesRuleState, nameChain, runRuleProducer, getCurrentChain,
    setCurrentChain) where

import qualified Control.Monad.Trans.State.Strict as ST
import Text.Printf (printf)

data State = State Int String

type IptablesRuleState = ST.State State

nameChain prefix = ST.state $ \(State idx chain) ->
    (printf "%s%d" prefix idx, State (idx+1) chain)

getCurrentChain :: IptablesRuleState String
getCurrentChain = fmap (\(State _ chain) -> chain) ST.get

setCurrentChain :: String -> IptablesRuleState ()
setCurrentChain chain = ST.modify $ (\(State idx _) -> State idx chain)

runRuleProducer :: IptablesRuleState a -> a
runRuleProducer f = ST.evalState f (State 0 "")
