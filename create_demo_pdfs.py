"""
Create sample PDF documents for testing
"""
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from datetime import datetime

def create_invoice_pdf():
    """Create a sample invoice PDF"""
    doc = SimpleDocTemplate("demo_data/sample_invoice.pdf", pagesize=A4)
    story = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1e3a8a'),
        spaceAfter=30,
        alignment=1  # Center
    )
    story.append(Paragraph("INVOICE", title_style))
    story.append(Spacer(1, 20))
    
    # Invoice details
    invoice_data = [
        ["Invoice #:", "INV-2025-001"],
        ["Date:", "December 18, 2025"],
        ["Due Date:", "January 18, 2026"],
    ]
    t = Table(invoice_data, colWidths=[2*inch, 3*inch])
    t.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.grey),
    ]))
    story.append(t)
    story.append(Spacer(1, 30))
    
    # Bill to section
    story.append(Paragraph("<b>Bill To:</b>", styles['Heading2']))
    story.append(Paragraph("Acme Corporation<br/>123 Business Street<br/>Paris, France 75001", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Services table
    story.append(Paragraph("<b>Services Provided:</b>", styles['Heading2']))
    story.append(Spacer(1, 10))
    
    services_data = [
        ["Description", "Amount"],
        ["Cloud Infrastructure Setup", "€5,000.00"],
        ["AWS ECS Configuration", "€3,500.00"],
        ["Database Migration", "€2,500.00"],
        ["Security Hardening", "€2,000.00"],
        ["", ""],
        ["Subtotal", "€13,000.00"],
        ["Tax (20%)", "€2,600.00"],
        ["<b>Total Amount Due</b>", "<b>€15,600.00</b>"],
    ]
    
    services_table = Table(services_data, colWidths=[4*inch, 1.5*inch])
    services_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -4), colors.beige),
        ('GRID', (0, 0), (-1, -4), 1, colors.black),
        ('LINEABOVE', (0, -3), (-1, -3), 2, colors.black),
        ('LINEABOVE', (0, -1), (-1, -1), 2, colors.HexColor('#1e3a8a')),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#e0e7ff')),
    ]))
    story.append(services_table)
    story.append(Spacer(1, 30))
    
    # Payment terms
    story.append(Paragraph("<b>Payment Terms:</b> Net 30 days", styles['Normal']))
    story.append(Paragraph("<b>Payment Method:</b> Bank Transfer", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Footer
    story.append(Paragraph("<i>Thank you for your business!</i>", styles['Normal']))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Contact: billing@techservices.com | Phone: +33 1 23 45 67 89", styles['Normal']))
    
    doc.build(story)
    print("[OK] Created sample_invoice.pdf")


def create_contract_pdf():
    """Create a sample contract PDF"""
    doc = SimpleDocTemplate("demo_data/sample_contract.pdf", pagesize=A4)
    story = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#1e3a8a'),
        spaceAfter=20,
        alignment=1
    )
    story.append(Paragraph("PROFESSIONAL SERVICES AGREEMENT", title_style))
    story.append(Spacer(1, 20))
    
    # Date
    story.append(Paragraph(f"<b>Effective Date:</b> {datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Parties
    story.append(Paragraph("<b>PARTIES:</b>", styles['Heading2']))
    story.append(Paragraph("This Agreement is entered into between:", styles['Normal']))
    story.append(Spacer(1, 10))
    
    parties_data = [
        ["Provider:", "Tech Services SARL, 45 Avenue des Champs-Élysées, 75008 Paris, France"],
        ["Client:", "Acme Corporation, 123 Business Street, 75001 Paris, France"],
    ]
    t = Table(parties_data, colWidths=[1.5*inch, 4.5*inch])
    t.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))
    
    # Terms
    story.append(Paragraph("<b>1. SCOPE OF SERVICES</b>", styles['Heading2']))
    story.append(Paragraph(
        "The Provider agrees to deliver cloud infrastructure consulting services, "
        "including but not limited to AWS architecture design, ECS containerization, "
        "and database optimization services as detailed in Exhibit A.",
        styles['Normal']
    ))
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("<b>2. TERM AND TERMINATION</b>", styles['Heading2']))
    story.append(Paragraph(
        "This Agreement shall commence on the Effective Date and continue for a period "
        "of twelve (12) months unless terminated earlier in accordance with this section. "
        "Either party may terminate this Agreement with thirty (30) days written notice.",
        styles['Normal']
    ))
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("<b>3. COMPENSATION</b>", styles['Heading2']))
    story.append(Paragraph(
        "Client agrees to pay Provider a monthly retainer of €10,000 EUR, payable "
        "within fifteen (15) days of invoice date. Additional services beyond the "
        "retainer scope will be billed at €150 EUR per hour.",
        styles['Normal']
    ))
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("<b>4. CONFIDENTIALITY</b>", styles['Heading2']))
    story.append(Paragraph(
        "Both parties agree to maintain confidentiality of all proprietary information "
        "disclosed during the term of this Agreement. This obligation shall survive "
        "termination of the Agreement for a period of three (3) years.",
        styles['Normal']
    ))
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("<b>5. INTELLECTUAL PROPERTY</b>", styles['Heading2']))
    story.append(Paragraph(
        "All deliverables created specifically for Client under this Agreement shall "
        "be the property of Client upon full payment. Provider retains ownership of "
        "pre-existing materials and general methodologies.",
        styles['Normal']
    ))
    story.append(Spacer(1, 30))
    
    # Signatures
    signature_data = [
        ["_____________________________", "_____________________________"],
        ["Provider Signature", "Client Signature"],
        ["Date: _____________", "Date: _____________"],
    ]
    sig_table = Table(signature_data, colWidths=[3*inch, 3*inch])
    sig_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
    ]))
    story.append(sig_table)
    
    doc.build(story)
    print("[OK] Created sample_contract.pdf")


if __name__ == "__main__":
    import os
    os.makedirs("demo_data", exist_ok=True)
    
    print("Creating sample PDF documents...")
    create_invoice_pdf()
    create_contract_pdf()
    print("\n[SUCCESS] All sample documents created!")

