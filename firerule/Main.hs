module Main where

import qualified System.IO as SIO
import qualified Text.Printf as Printf
import qualified Options.Applicative as Opt
import Control.Applicative((<**>))
import Data.Semigroup((<>))

import qualified Firerule.Firewall as Firewall
import qualified Firerule.Iptables.Iptables as Iptables
import qualified Firerule.Format.RuleParser as RuleParser
import qualified Firerule.Format.ConfBuilder as ConfBuilder

data Config = Config {
        firewallFile :: String,
        dryRun :: Bool
    }

configParse = Config <$>
    Opt.strArgument (Opt.metavar "FILE") <*>
    Opt.switch (Opt.short 's' <> Opt.help "only show the rules")

main = do
    config <- Opt.execParser $
        Opt.info (configParse <**> Opt.helper) Opt.fullDesc
    SIO.withFile (firewallFile config) SIO.ReadMode $ \h -> do
        inp <- SIO.hGetContents h
        case RuleParser.parseFirewall inp >>= ConfBuilder.buildConf of
          Left err -> putStrLn $ Printf.printf "failure: %s" err
          Right fw -> if not $ dryRun config
                          then apply Iptables.IptablesFirewall fw
                          else apply Iptables.IptablesPrintFirewall fw
    where apply fh fw = Firewall.create fh fw >>= Firewall.use fh
