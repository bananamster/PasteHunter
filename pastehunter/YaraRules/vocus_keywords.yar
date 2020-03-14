/*
    This rule is for searching for Vocus specific mentions, it will match any of the keywords in the list
*/

rule vocus_keywords
{
    meta:
        author = "@Bananamaster300"
        info = "Rule for Vocus PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $domain001 = "2talk.co.nz" wide ascii nocase
        $domain002 = "amcom.co.nz" wide ascii nocase
        $domain003 = "attica.co.nz" wide ascii nocase
        $domain004 = "attica.net.nz" wide ascii nocase
        $domain005 = "bizo.co.nz" wide ascii nocase
        $domain006 = "bizoservices.com" wide ascii nocase
        $domain007 = "bw.co.nz" wide ascii nocase
        $domain008 = "bw.nz" wide ascii nocase
        $domain009 = "callplus.co.nz" wide ascii nocase
        $domain010 = "callplus.net.nz" wide ascii nocase
        $domain011 = "callplus.nz" wide ascii nocase
        $domain012 = "callplussales.co.nz" wide ascii nocase
        $domain013 = "commverge.co.nz" wide ascii nocase
        $domain014 = "commverge.net.nz" wide ascii nocase
        $domain015 = "connected.net.nz" wide ascii nocase
        $domain016 = "cosmos.net.nz" wide ascii nocase
        $domain017 = "cpg.co.nz" wide ascii nocase
        $domain018 = "cpmail.co.nz" wide ascii nocase
        $domain019 = "fiberme.co.nz" wide ascii nocase
        $domain020 = "fibreme.com" wide ascii nocase
        $domain021 = "fibreme.net" wide ascii nocase
        $domain022 = "fibreme.net.nz" wide ascii nocase
        $domain023 = "flip.co.nz" wide ascii nocase
        $domain024 = "fx.net.nz" wide ascii nocase
        $domain025 = "geniusgo.co.nz" wide ascii nocase
        $domain026 = "geniusgo.net.nz" wide ascii nocase
        $domain027 = "gotalk.co.nz" wide ascii nocase
        $domain028 = "i4free.co.nz" wide ascii nocase
        $domain029 = "i4free.net.nz" wide ascii nocase
        $domain030 = "internet4free.co.nz" wide ascii nocase
        $domain031 = "internet-support.co.nz" wide ascii nocase
        $domain032 = "iserve.net.nz" wide ascii nocase
        $domain033 = "italk.co.nz" wide ascii nocase
        $domain034 = "linetest.co.nz" wide ascii nocase
        $domain035 = "linetest.net.nz" wide ascii nocase
        $domain036 = "linetest.nz" wide ascii nocase
        $domain037 = "m2group.co.nz" wide ascii nocase
        $domain038 = "m2nz.co.nz" wide ascii nocase
        $domain039 = "m2nz.nz" wide ascii nocase
        $domain040 = "maxnet.co.nz" wide ascii nocase
        $domain041 = "maxnet.net.nz" wide ascii nocase
        $domain042 = "myinternet.net.nz" wide ascii nocase
        $domain043 = "orcon.co.nz" wide ascii nocase
        $domain044 = "orcon.net" wide ascii nocase
        $domain045 = "orcon.net.nz" wide ascii nocase
        $domain046 = "orcon.nz" wide ascii nocase
        $domain047 = "orconhosting.co.nz" wide ascii nocase
        $domain048 = "orconhosting.net.nz" wide ascii nocase
        $domain049 = "orconsecurity.co.nz" wide ascii nocase
        $domain050 = "orconsecurity.net.nz" wide ascii nocase
        $domain051 = "prodns.net.nz" wide ascii nocase
        $domain052 = "slingshot.co.nz" wide ascii nocase
        $domain053 = "slingshot.net.nz" wide ascii nocase
        $domain054 = "slingshot.nz" wide ascii nocase
        $domain055 = "smb2go.net" wide ascii nocase
        $domain056 = "switchclubpower.co.nz" wide ascii nocase
        $domain057 = "switchclubpower.nz" wide ascii nocase
        $domain058 = "switchsaver.co.nz" wide ascii nocase
        $domain059 = "switchutilities.co.nz" wide ascii nocase
        $domain060 = "switchutilities.nz" wide ascii nocase
        $domain061 = "t3.co.nz" wide ascii nocase
        $domain062 = "t3.net.nz" wide ascii nocase
        $domain063 = "t3.nz" wide ascii nocase
        $domain064 = "t3i.co.nz" wide ascii nocase
        $domain065 = "t3i.net.nz" wide ascii nocase
        $domain066 = "t3i.nz" wide ascii nocase
        $domain067 = "tranzpeer.net" wide ascii nocase
        $domain068 = "visibill.co.nz" wide ascii nocase
        $domain069 = "visp.nz" wide ascii nocase
        $domain070 = "vocus.net.nz" wide ascii nocase
        $domain071 = "vocus.co.nz" wide ascii nocase
        $domain072 = "vocus.local" wide ascii nocase
        $domain073 = "vocus.net.nz" wide ascii nocase
        $domain074 = "vocus.nz" wide ascii nocase
        $domain075 = "vocusconnect.co.nz" wide ascii nocase
        $domain076 = "vocusgroup.co.nz" wide ascii nocase
        $domain077 = "vocusgroup.net.nz" wide ascii nocase
        $domain078 = "vocusgroup.nz" wide ascii nocase
        $domain079 = "vocusgrouplimited.co.nz" wide ascii nocase
        $domain080 = "vocusgroupltd.co.nz" wide ascii nocase
        $domain081 = "vocuslimited.co.nz" wide ascii nocase
        $domain082 = "vocusmail.co.nz" wide ascii nocase
    condition:
        any of them

}
