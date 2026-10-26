//go:build !windows

package main

import "errors"

func openBrowser(url string) error {
	return errors.New("ouvrez manuellement l'adresse locale affichée")
}
func pickFolder() (string, error) {
	return "", errors.New("le sélecteur natif nécessite Windows; saisissez un chemin local")
}
