def makeDatasheetChanges(sheet, shieldFlag):
    for cranePrize in sheet['values']:
        # Shield should not be obtainable until you find your first shield
        if cranePrize['symbol'] == 'Shield':
            cranePrize['layouts'][0]['conditions'].append({'category': 1, 'parameter': shieldFlag})

        # SmallBowWow (Ciao Ciao): Remove the condition of HintYosshi. It's unnecessary and can lead to a softlock
        if cranePrize['symbol'] == 'SmallBowWow':
            cranePrize['layouts'][0]['conditions'].pop(0)

        # BowWow: Remove the ShadowClear condition. This was stupid in vanilla and it's even worse for rando.
        if cranePrize['symbol'] == 'BowWow':
            cranePrize['layouts'][0]['conditions'].pop(0)
