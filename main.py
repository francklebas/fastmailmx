from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel, EmailStr
import dns.resolver
import smtplib
import socket

# Initialisation de l'application
app = FastAPI(
    title="Email & MX Verifier API",
    description="API haute performance pour vérifier la validité des emails et l'existence des serveurs MX.",
    version="1.0.0"
)

# Modèle de données pour valider l'entrée (Input)
class EmailRequest(BaseModel):
    email: EmailStr  # Utilise Pydantic pour une pré-validation du format standard

@app.get("/")
def read_root():
    return {"status": "online", "message": "Email Verifier is running. Use POST /verify to check emails."}

@app.post("/verify")
def verify_email(request: EmailRequest = Body(...)):
    email = request.email
    domain = email.split('@')[-1]
    
    mx_record_found = False
    mx_servers = []
    
    # Configuration du résolveur DNS avec un timeout strict
    # (Important pour la rapidité de l'API)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    try:
        # Recherche des enregistrements MX (Mail Exchange)
        answers = resolver.resolve(domain, 'MX')
        mx_record_found = True
        # On récupère la liste des serveurs mail pour info
        mx_servers = [r.exchange.to_text() for r in answers]
        
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        mx_record_found = False
    except Exception as e:
        # En cas d'erreur technique (timeout DNS), on renvoie false par sécurité
        mx_record_found = False

    # Logique de scoring
    status = "invalid"
    if mx_record_found:
        status = "valid"
    else:
        status = "invalid_domain"

    return {
        "email": email,
        "format_valid": True,  # Si on est ici, Pydantic a déjà validé le format
        "mx_found": mx_record_found,
        "status": status,
        "domain": domain,
        "mx_servers": mx_servers[:2] # On renvoie max 2 serveurs pour info
    }

# Lancement local (uniquement si exécuté directement)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
