rule Log4j_request {
   meta:
      description = "Detects generic log4j requests. Include malicious callback attempts, but may contain false positives"
      author = "Jonathon Sweeney"
      reference = "Log4j Research"
      date = "2022-01-06"

   strings:

      $s1 = "${jndi:${lower:l}${lower:d}a${lower:p}:" nocase wide ascii
      $s2 = "JHtqbmRpOiR7bG93ZXI6bH0ke2xvd2VyOmR9YSR7bG93ZXI6cH06"
      $s3 = "${jndi:ldap://" nocase wide ascii
      $s4 = "asciiJHtqbmRpOmxkYXA6Ly8=" nocase wide 


   condition:
      any of ($s*)
}
