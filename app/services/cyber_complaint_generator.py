from datetime import datetime


def generate_cyber_complaint_text(
    user_name: str,
    phone: str,
    email: str,
    scam_type: str,
    incident_date: str,
    loss_amount: str | None,
    description: str,
):
    return f"""
To,
The Cyber Crime Cell,

I, {user_name}, would like to report a cyber crime incident that occurred on {incident_date}.

Type of Cyber Crime:
{scam_type}

Registered Email ID:
{email}

Registered Mobile Number:
{phone}

Financial Loss (if any):
{loss_amount or "No financial loss reported"}

Incident Description:
{description}

I request the concerned authorities to kindly investigate the matter and take necessary action as per the law.

I hereby declare that the information provided above is true and correct to the best of my knowledge.

Date of Complaint:
{datetime.utcnow().strftime("%d-%m-%Y")}

Regards,
{user_name}
"""
