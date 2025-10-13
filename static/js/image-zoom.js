document.addEventListener('DOMContentLoaded', function() {
    // Sélectionne toutes les images dans le contenu
    const images = document.querySelectorAll('article img, .content img, main img');
    
    images.forEach(img => {
        // Rend l'image cliquable
        img.style.cursor = 'pointer';
        
        img.addEventListener('click', function() {
            // Crée l'overlay
            const overlay = document.createElement('div');
            overlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.9);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 9999;
                cursor: zoom-out;
            `;
            
            // Clone l'image
            const zoomedImg = img.cloneNode();
            zoomedImg.style.cssText = `
                max-width: 90%;
                max-height: 90%;
                object-fit: contain;
                box-shadow: 0 0 30px rgba(0, 0, 0, 0.5);
            `;
            
            overlay.appendChild(zoomedImg);
            document.body.appendChild(overlay);
            
            // Ferme au clic
            overlay.addEventListener('click', function() {
                document.body.removeChild(overlay);
            });
            
            // Ferme avec Echap
            document.addEventListener('keydown', function closeOnEsc(e) {
                if (e.key === 'Escape') {
                    if (document.body.contains(overlay)) {
                        document.body.removeChild(overlay);
                    }
                    document.removeEventListener('keydown', closeOnEsc);
                }
            });
        });
    });
});
