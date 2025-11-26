/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const requested = query.to as string

    if (!requested) {
      res.status(400)
      return next(new Error('Missing target URL for redirect'))
    }

    /**
     * Strict allow-list:
     * Instead of checking if requested URL "includes" an allowed one,
     * we lookup an exact match in redirectAllowlist.
     * This removes all user-controlled input from the redirect sink.
     */
    const toUrl = [...security.redirectAllowlist].find(
      (allowed) => allowed === requested
    )

    if (!toUrl) {
      res.status(406)
      return next(new Error('Unrecognized target URL for redirect: ' + requested))
    }

    /* Challenge completion logic (unchanged, now uses sanitized toUrl) */
    challengeUtils.solveIf(
      challenges.redirectCryptoCurrencyChallenge,
      () => {
        return (
          toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' ||
          toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' ||
          toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
        )
      }
    )

    challengeUtils.solveIf(
      challenges.redirectChallenge,
      () => isUnintendedRedirect(toUrl)
    )

    /* SAFE redirect — only using strict allow-list values */
    return res.redirect(toUrl)
  }
}

/**
 * “Unintended” now simply means "not in the allow-list".
 * But we include this function because challenges rely on it.
 */
function isUnintendedRedirect (toUrl: string) {
  return !security.redirectAllowlist.has(toUrl)
}
