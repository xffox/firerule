module Main where

import Criterion.Main

import qualified Firerule.IPv4 as IPv4
import qualified Firerule.IPv6 as IPv6
import qualified Firerule.IP as IP

main =
    defaultMain [
        bgroup "ipv4" [
            bench "subnets" $ nf (\prefixLen -> length $
                IP.subnets (IPv4.ipv4net (0,0,0,0) 0) prefixLen) 24
            ],
        bgroup "ipv6" [
            bench "subnets" $ nf (\prefixLen -> length $
                IP.subnets (IPv6.ipv6net (0,0,0,0,0,0,0,0) 0) prefixLen) 24
            ]
        ]
