# DDI-Buntu : menu console à la connexion interactive d'un administrateur (groupe ddiadmin).
if [ -z "${DDI_MENU_DONE:-}" ] && [ -x /usr/local/bin/ddibuntu-menu ] && [ -t 0 ] && [ -t 1 ]; then
  case " $(id -nG 2>/dev/null) " in
    *" ddiadmin "*) DDI_MENU_DONE=1; export DDI_MENU_DONE; /usr/local/bin/ddibuntu-menu ;;
  esac
fi
