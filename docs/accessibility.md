# Accessibilité et design system

## Palette et contraste

Palette fixe : navy `#0A1F44`, teal `#006f68`/`#075b65`, texte `#10233f`, fond `#f6f8fb`, fond sidebar `#eaf0f5`. Contrastes calculés avec la formule WCAG relative luminance (ratio minimum 4,5:1 pour texte normal) :

| Premier plan | Arrière-plan | Ratio calculé |
|---|---|---:|
| `#10233f` | `#f6f8fb` | 14,79:1 |
| `#10233f` | `#eaf0f5` | 13,70:1 |
| `#ffffff` | `#006f68` | 6,05:1 |
| `#efffff` | `#075b65` | 7,58:1 |
| `#ffffff` | `#0A1F44` | 16,25:1 |

Les textes du bandeau dégradé blanc/menthe restent à au moins 7,58:1 aux extrémités. Vérification calculée localement, pas certifiée par audit externe. Retester les états réellement rendus et les changements de thème avant diffusion.

## Clavier, texte alternatif et responsive

- Formulaires natifs Streamlit avec libellés textuels et ordre de navigation standard.
- Focus explicite au clavier (contour navy de 3 px).
- Aucun fichier image ou pictogramme décoratif externe n’est utilisé. Les résultats/explications de graphiques sont également affichés en tableau ou expliqués en texte ; les pastilles de confiance ont un libellé textuel.
- Styles réduisent les marges et les métriques sous 640 px ; vérifier sur un appareil mobile réel.
- La page utilise la pile système Segoe UI/Arial ; pas de police distante.

Cette checklist n’est pas un audit WCAG complet (lecteur d’écran, zoom, contraste de tous les composants Streamlit tiers et tests mobiles réels à compléter).
