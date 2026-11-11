// Une réponse 401 ne veut pas toujours dire « votre session a expiré » : seule l'absence de session (code « unauthenticated »)
// renvoie à la page de connexion. Tout autre refus est un résultat à afficher, pas une déconnexion.
export function isSessionExpired(status: number, code: string): boolean {
  return status === 401 && code === 'unauthenticated'
}
