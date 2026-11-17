// Générateur des profils EJBCA fournis par le DDI (0.14.3). Il s'exécute DANS le conteneur EJBCA (java Gen.java DOSSIER) avec les bibliothèques de la CLI
// d'EJBCA : les profils sont donc construits par le code d'EJBCA lui-même (tous les réglages par défaut présents) puis sérialisés comme le fait « ca exportprofiles »,
// ce qu'un XML écrit à la main ne garantirait pas. Lancé par tools/pki-gen-profiles.sh ; la sortie est versionnée dans
// src/rootfs/usr/local/lib/ddibuntu/pki-profiles/ (ne pas la modifier à la main).
//
// Identifiants fixes : un profil déjà présent dans la base d'EJBCA n'est jamais réimporté (ddibuntu-pki le contrôle avant d'importer).
//   5010001 DDI-RADIUS-Server    serveur RADIUS (EAP-TLS) : serverAuth, 730 jours
//   5010002 DDI-Client-Machine   poste ou machine (EAP-TLS machine) : clientAuth, 365 jours
//   5010003 DDI-Client-User      utilisateur (EAP-TLS utilisateur, UPN Microsoft) : clientAuth, 365 jours
//   5010004 DDI-Network-Device   équipement réseau, SCEP : serverAuth + clientAuth, 365 jours
//   5020001 DDI-Endentity        profil d'entité finale commun : toutes autorités, nos quatre profils, champs de nom et de SAN utiles
// Chaque certificat reprend les adresses de CRL (CDP) et de certificat de l'autorité (AIA) DÉFINIES PAR L'AUTORITÉ (ca editca, posées à sa création) : une
// adresse OCSP n'est pas gravée (le répondeur d'une CE ne sert une autorité créée à chaud qu'après un redémarrage).
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import java.beans.XMLEncoder;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;

public class Gen {
  static final String SERVER = "1.3.6.1.5.5.7.3.1", CLIENT = "1.3.6.1.5.5.7.3.2";
  static final int[] IDS = { 5010001, 5010002, 5010003, 5010004 };

  static void write(String file, Object map) throws Exception {
    try (XMLEncoder e = new XMLEncoder(new BufferedOutputStream(new FileOutputStream(file)))) { e.writeObject(map); }
  }

  static CertificateProfile make(String validity, String... eku) throws Exception {
    CertificateProfile p = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    p.setEncodedValidity(validity);
    p.setUseKeyUsage(true); p.setKeyUsageCritical(true);
    p.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
    p.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
    p.setKeyUsage(CertificateConstants.NONREPUDIATION, false);
    p.setKeyUsage(CertificateConstants.DATAENCIPHERMENT, false);
    p.setUseExtendedKeyUsage(true); p.setExtendedKeyUsageCritical(false);
    p.setExtendedKeyUsageOids(new ArrayList<>(Arrays.asList(eku)));
    // adresses de CRL et de certificat de l'AUTORITÉ (ca editca defaultCRLDistPoint / certificateAiaDefaultCaIssuerUri), jamais d'adresse OCSP
    p.setUseCRLDistributionPoint(true); p.setUseDefaultCRLDistributionPoint(true); p.setCRLDistributionPointCritical(false);
    p.setUseAuthorityInformationAccess(true); p.setUseDefaultCAIssuer(true); p.setUseDefaultOCSPServiceLocator(false);
    p.setUseSubjectAlternativeName(true); p.setStoreSubjectAlternativeName(true);
    p.setUseSubjectKeyIdentifier(true); p.setUseAuthorityKeyIdentifier(true);
    // aucune dérogation : ni durée, ni nom, ni extension ne viennent de la demande de certificat
    p.setAllowValidityOverride(false); p.setAllowDNOverride(false); p.setAllowExtensionOverride(false); p.setAllowKeyUsageOverride(false);
    p.setAvailableCAs(new ArrayList<>(Arrays.asList(CertificateProfile.ANYCA)));
    p.setAvailableKeyAlgorithmsAsList(new ArrayList<>(Arrays.asList("RSA", "ECDSA")));
    p.setAvailableBitLengthsAsList(new ArrayList<>(Arrays.asList(2048, 3072, 4096)));
    p.setAvailableEcCurvesAsList(new ArrayList<>(Arrays.asList("prime256v1", "secp384r1")));
    return p;
  }

  public static void main(String[] a) throws Exception {
    String d = a[0];
    write(d + "/certprofile_DDI-RADIUS-Server-" + IDS[0] + ".xml", make("730d", SERVER).saveData());
    write(d + "/certprofile_DDI-Client-Machine-" + IDS[1] + ".xml", make("365d", CLIENT).saveData());
    write(d + "/certprofile_DDI-Client-User-" + IDS[2] + ".xml", make("365d", CLIENT).saveData());
    write(d + "/certprofile_DDI-Network-Device-" + IDS[3] + ".xml", make("365d", SERVER, CLIENT).saveData());

    EndEntityProfile e = new EndEntityProfile(true);
    for (int f : new int[] { DNFieldExtractor.O, DNFieldExtractor.OU, DNFieldExtractor.C }) e.addField(f);
    for (int i = 0; i < 8; i++) e.addField(DNFieldExtractor.DNSNAME);
    for (int i = 0; i < 4; i++) e.addField(DNFieldExtractor.IPADDRESS);
    for (int i = 0; i < 2; i++) e.addField(DNFieldExtractor.RFC822NAME);
    for (int i = 0; i < 2; i++) e.addField(DNFieldExtractor.UPN);
    e.setAvailableCertificateProfileIds(new ArrayList<>(Arrays.asList(IDS[0], IDS[1], IDS[2], IDS[3])));
    e.setDefaultCertificateProfile(IDS[0]);
    e.setAvailableCAs(new ArrayList<>(Arrays.asList(EndEntityConstants.EEP_ANY_CA)));
    e.setDefaultCA(EndEntityConstants.EEP_ANY_CA);
    e.setAvailableTokenTypes(new ArrayList<>(Arrays.asList(EndEntityConstants.TOKEN_USERGEN)));
    e.setDefaultTokenType(EndEntityConstants.TOKEN_USERGEN);
    write(d + "/entityprofile_DDI-Endentity-5020001.xml", e.saveData());
  }
}
