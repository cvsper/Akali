#!/usr/bin/env python3
"""
Akali Certificate Generator - Generate PDF training certificates

Creates professional PDF certificates for completed training modules.
Uses ReportLab for PDF generation.
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
import os

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class CertificateGenerator:
    """Generate professional security training certificates"""

    def __init__(self, output_dir: str = None):
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "ReportLab is required for certificate generation. "
                "Install it with: pip install reportlab"
            )

        if output_dir is None:
            # Default to ~/.akali/certificates/
            output_dir = Path.home() / ".akali" / "certificates"

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Akali brand colors (from SOUL.md theme)
        self.primary_color = HexColor('#6B46C1')  # Purple
        self.accent_color = HexColor('#F59E0B')   # Orange
        self.text_color = black

    def generate_certificate(
        self,
        agent_id: str,
        module_title: str,
        module_id: str,
        score: int,
        total_questions: int,
        percentage: float,
        issued_date: str = None
    ) -> str:
        """Generate a certificate PDF and return the file path"""

        if issued_date is None:
            issued_date = datetime.now().strftime("%B %d, %Y")

        # Create filename
        filename = f"akali_certificate_{agent_id}_{module_id}_{datetime.now().strftime('%Y%m%d')}.pdf"
        filepath = self.output_dir / filename

        # Create PDF
        c = canvas.Canvas(str(filepath), pagesize=letter)
        width, height = letter

        # Draw certificate
        self._draw_border(c, width, height)
        self._draw_header(c, width, height)
        self._draw_title(c, width, height)
        self._draw_recipient(c, width, height, agent_id)
        self._draw_achievement(c, width, height, module_title)
        self._draw_score(c, width, height, score, total_questions, percentage)
        self._draw_footer(c, width, height, issued_date)
        self._draw_signature(c, width, height)

        # Save PDF
        c.showPage()
        c.save()

        return str(filepath)

    def _draw_border(self, c: canvas.Canvas, width: float, height: float):
        """Draw decorative border"""
        c.setStrokeColor(self.primary_color)
        c.setLineWidth(3)
        c.rect(0.5*inch, 0.5*inch, width - inch, height - inch)

        c.setStrokeColor(self.accent_color)
        c.setLineWidth(1)
        c.rect(0.6*inch, 0.6*inch, width - 1.2*inch, height - 1.2*inch)

    def _draw_header(self, c: canvas.Canvas, width: float, height: float):
        """Draw certificate header with Akali branding"""
        c.setFillColor(self.primary_color)
        c.setFont("Helvetica-Bold", 32)
        c.drawCentredString(width / 2, height - 1.5*inch, "🥷 AKALI")

        c.setFillColor(self.text_color)
        c.setFont("Helvetica", 16)
        c.drawCentredString(width / 2, height - 1.9*inch, "The Security Sentinel")

    def _draw_title(self, c: canvas.Canvas, width: float, height: float):
        """Draw certificate title"""
        c.setFillColor(self.accent_color)
        c.setFont("Helvetica-Bold", 28)
        c.drawCentredString(width / 2, height - 2.7*inch, "Certificate of Completion")

    def _draw_recipient(self, c: canvas.Canvas, width: float, height: float, agent_id: str):
        """Draw recipient information"""
        c.setFillColor(self.text_color)
        c.setFont("Helvetica", 14)
        c.drawCentredString(width / 2, height - 3.4*inch, "This certifies that")

        c.setFillColor(self.primary_color)
        c.setFont("Helvetica-Bold", 24)
        c.drawCentredString(width / 2, height - 3.9*inch, agent_id.upper())

    def _draw_achievement(self, c: canvas.Canvas, width: float, height: float, module_title: str):
        """Draw achievement details"""
        c.setFillColor(self.text_color)
        c.setFont("Helvetica", 14)
        c.drawCentredString(width / 2, height - 4.5*inch, "has successfully completed")

        # Handle long module titles (wrap if needed)
        c.setFont("Helvetica-Bold", 18)
        if len(module_title) > 50:
            # Split into two lines
            words = module_title.split()
            mid = len(words) // 2
            line1 = ' '.join(words[:mid])
            line2 = ' '.join(words[mid:])
            c.drawCentredString(width / 2, height - 5.1*inch, line1)
            c.drawCentredString(width / 2, height - 5.5*inch, line2)
        else:
            c.drawCentredString(width / 2, height - 5.2*inch, module_title)

    def _draw_score(self, c: canvas.Canvas, width: float, height: float,
                    score: int, total_questions: int, percentage: float):
        """Draw score information"""
        c.setFillColor(self.text_color)
        c.setFont("Helvetica", 12)
        y = height - 6.3*inch if percentage > 50 else height - 6.3*inch

        score_text = f"Score: {score}/{total_questions} ({percentage:.1f}%)"
        c.drawCentredString(width / 2, y, score_text)

        # Add achievement badge if excellent score
        if percentage >= 90:
            c.setFillColor(self.accent_color)
            c.setFont("Helvetica-Bold", 14)
            c.drawCentredString(width / 2, y - 0.4*inch, "⭐ EXCELLENT PERFORMANCE ⭐")
        elif percentage >= 80:
            c.setFillColor(self.primary_color)
            c.setFont("Helvetica-Bold", 12)
            c.drawCentredString(width / 2, y - 0.4*inch, "✨ GREAT JOB ✨")

    def _draw_footer(self, c: canvas.Canvas, width: float, height: float, issued_date: str):
        """Draw certificate footer with date"""
        c.setFillColor(self.text_color)
        c.setFont("Helvetica", 11)
        c.drawCentredString(width / 2, 1.8*inch, f"Issued on {issued_date}")

        c.setFont("Helvetica-Oblique", 9)
        c.drawCentredString(width / 2, 1.4*inch, "Akali Security Training Program")
        c.drawCentredString(width / 2, 1.2*inch, "Protecting the family, one agent at a time")

    def _draw_signature(self, c: canvas.Canvas, width: float, height: float):
        """Draw signature line"""
        # Signature line
        line_start = width / 2 - 1.5*inch
        line_end = width / 2 + 1.5*inch
        y = 2.5*inch

        c.setStrokeColor(self.text_color)
        c.setLineWidth(1)
        c.line(line_start, y, line_end, y)

        # Signature label
        c.setFillColor(self.text_color)
        c.setFont("Helvetica-Bold", 11)
        c.drawCentredString(width / 2, y - 0.3*inch, "Akali 🥷")

        c.setFont("Helvetica", 9)
        c.drawCentredString(width / 2, y - 0.5*inch, "Security Sentinel")


def generate_test_certificate():
    """Generate a test certificate for demonstration"""
    if not REPORTLAB_AVAILABLE:
        print("❌ ReportLab not installed. Install with: pip install reportlab")
        return

    generator = CertificateGenerator()

    filepath = generator.generate_certificate(
        agent_id="dommo",
        module_title="OWASP #1: Injection Attacks",
        module_id="owasp_01_injection",
        score=5,
        total_questions=5,
        percentage=100.0,
        issued_date=datetime.now().strftime("%B %d, %Y")
    )

    print(f"✅ Certificate generated: {filepath}")
    print(f"📄 Open with: open '{filepath}'")


if __name__ == '__main__':
    generate_test_certificate()
