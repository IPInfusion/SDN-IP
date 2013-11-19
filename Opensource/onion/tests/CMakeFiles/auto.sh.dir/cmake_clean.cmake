FILE(REMOVE_RECURSE
  "CMakeFiles/auto.sh"
)

# Per-language clean rules from dependency scanning.
FOREACH(lang)
  INCLUDE(CMakeFiles/auto.sh.dir/cmake_clean_${lang}.cmake OPTIONAL)
ENDFOREACH(lang)
