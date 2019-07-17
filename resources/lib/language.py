from matthuisman.language import BaseLanguage

class Language(BaseLanguage):

    ASK_USERNAME           = 30001
    ASK_PASSWORD           = 30002
    NO_CHANNEL             = 30003
    LOGIN_ERROR            = 30004
    ADOBE_ERROR            = 30005
    TOKEN_ERROR            = 30006
    LIVE_TV                = 30007

    TV_SHOWS               = 30010
    MOVIES                 = 30011
    SPORTS                 = 30012
    BOX_SETS               = 30013
    PLAY_ERROR             = 30014
    EPISODE_LABEL          = 30015
    RENEW_TOKEN_ERROR      = 30016
    SAVE_PASSWORD          = 30017
    HIDE_UNPLAYABLE        = 30018
    LOCKED                 = 30019
    ADOBE_DRM              = 30020
    NEXT_PAGE              = 30021

_ = Language()