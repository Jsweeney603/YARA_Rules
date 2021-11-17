rule malicious_browser_update {
   meta:
      description = "Malicious Browser Update 'Javascript' files - Microsoft Edge, Mozilla Firefox, Google Chrome"
      author = "Jonathon Sweeney"
      reference = "Internal Research"
      date = "2021-11-17"
      
   strings:
      $s1 = "+ encodeURIComponent(''+" fullword ascii
      $s2 = "= (new Date)['getTime']();" fullword ascii
      $s4 = "['open']('POST'," ascii
      $s6 = "['substr'](2);" fullword ascii
      $s8 = " = new ActiveXObject('MSXML2.XMLHTTP');" fullword ascii
      $s9 = "['toString']" fullword ascii
      $s10 = "return" fullword ascii
      $s12 = "['send']" fullword ascii
      $s13 = "function" fullword ascii
      $s14 = "['status']" fullword ascii
      $s17 = "sendRequest(" fullword ascii
      $s18 = "while (" fullword ascii
      $s19 = "['responseText'];" fullword ascii
      $s20 = "String['fromCharCode']" fullword ascii
      $s21 = "+ 10000;" fullword ascii
      $s22 =  "= '';" fullword ascii
      $s23 = "if(typeof" fullword ascii

   condition:
      uint16(0) == 0x6176 and filesize < 7KB and
      8 of them
}
