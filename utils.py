import os

import tarfile
import zipfile
from shutil import ReadError
from zipfile import ZipFile
from py7zr import unpack_7zarchive, UnsupportedCompressionMethodError

import aiofiles
import aioshutil
import patoolib

SOURCEGRAPH_SEARCH_OPTIONS = 'context:global archived:yes fork:yes count:all'

IGNORED_REPOS = [
    "github.com/apache/airflow-site",
    "github.com/Be-Secure/besecure-assessment-datastore",
    "github.com/chainguard-dev/bom-shelter",
    "github.com/chains-project/SBOM-2023",
    "github.com/chains-project/sbom-files",
    "github.com/cybeats/sbomgen",
    "github.com/CycloneDX/bom-examples",
    "github.com/CycloneDX/cyclonedx-dotnet-library",
    "github.com/endorlabs/sbom-lab",
    "github.com/garethr/snyk-sbom-examples",
    "github.com/guacsec/guac-data",
    "github.com/k3rn3Lp4n1cK/ctf-live-build-config",
    "github.com/maxhbr/LicenseScannerComparison",
    "github.com/mercedes-benz/sechub",
    "github.com/nexB/spdx-license-namespaces-registry",
    "github.com/Open-Source-Compliance/package-analysis",
    "github.com/opencybersecurityalliance/casp",
    "github.com/OSSQA-PUM/OSSQA",
    "github.com/PanZheng-2021/xhs",
    "github.com/phil2211/deciphering_complexity",
    "github.com/rad-security/fingerprints",
    "github.com/sonatype-nexus-community/cyclonedx-sbom-examples",
    "github.com/spdx/spdx-examples",
    "github.com/spdx/license-list-data",
    "github.com/SEMICeu/DCAT-AP",
]

# create valid regex filter for ignored repos
REPO_FILTERS = [
    r'^github\.com/('
]
for repo in IGNORED_REPOS:
    REPO_FILTERS[0] += repo[repo.find("/") + 1:] + '|'
REPO_FILTERS[0] = REPO_FILTERS[0][:-1] + r')$'

# REPO_FILTERS = [
#    r'^github\.com/(apache/airflow-site|Be-Secure/besecure-assessment-datastore|chainguard-dev/bom-shelter|chains-project/SBOM-2023|chains-project/sbom-files|cybeats/sbomgen|CycloneDX/bom-examples|CycloneDX/cyclonedx-dotnet-library|endorlabs/sbom-lab|garethr/snyk-sbom-examples|guacsec/guac-data|k3rn3Lp4n1cK/ctf-live-build-config|maxhbr/LicenseScannerComparison|mercedes-benz/sechub|Open-Source-Compliance/package-analysis|opencybersecurityalliance/casp|OSSQA-PUM/OSSQA|PanZheng-2021/xhs|phil2211/deciphering_complexity|rad-security/fingerprints|sonatype-nexus-community/cyclonedx-sbom-examples)$'
# ]

FILE_FILTERS = [
    r'^.*(vendor|reference|resources|tools|3rdparty|bundled|contrib|demo|dependency|example|expect|external|fixture|inspector-scan|\/lib\/|libraries|libs\/|modules|package|packages\/|pcg|pcg-cpp|\/pkg\/|sample\/|samples\/|schema|template|test|third(-|_|\/|)party|vcpkg|worker(s|)\/).*$',
    r'^(lib\/).*$'
]

KNOWN_NOT_SBOM_EXTENSIONS = [
    r'^.*(.123|\.3dml|\.3ds|\.3g2|\.3gp|\.7z|\.aab|\.aac|\.aam|\.aas|\.abw|\.ac|\.acc|\.ace|\.acu|\.acutc|\.adp|\.aep|\.afm|\.afp|\.ahead|\.ai|\.aif|\.aifc|\.aiff|\.air|\.ait|\.ami|\.apk|\.appcache|\.application|\.apr|\.arc|\.asc|\.asf|\.asm|\.aso|\.asx|\.atc|\.atom|\.atomcat|\.atomsvc|\.atx|\.au|\.avi|\.aw|\.azf|\.azs|\.azw|\.bat|\.bcpio|\.bdf|\.bdm|\.bed|\.bh2|\.bin|\.blb|\.blend|\.blorb|\.bmi|\.bmp|\.book|\.box|\.boz|\.bpk|\.btif|\.bz|\.bz2|\.c|\.c11amc|\.c11amz|\.c4d|\.c4f|\.c4g|\.c4p|\.c4u|\.cab|\.caf|\.cap|\.car|\.cat|\.cb7|\.cba|\.cbr|\.cbt|\.cbz|\.cc|\.cct|\.ccxml|\.cdbcmsg|\.cdf|\.cdkey|\.cdmia|\.cdmic|\.cdmid|\.cdmio|\.cdmiq|\.cdr|\.cdx|\.cdxml|\.cdy|\.cer|\.cfs|\.cgm|\.chat|\.chm|\.chrt|\.cif|\.cii|\.cil|\.cla|\.class|\.clkk|\.clkp|\.clkt|\.clkw|\.clkx|\.clp|\.cmc|\.cmdf|\.cml|\.cmp|\.cmx|\.cod|\.com|\.conf|\.cpio|\.cpp|\.cpt|\.crd|\.crl|\.crt|\.cryptonote|\.csh|\.csml|\.csp|\.css|\.cst|\.csv|\.cu|\.curl|\.cww|\.cxt|\.cxx|\.dae|\.daf|\.dart|\.dataless|\.davmount|\.dbk|\.dcr|\.dcurl|\.dd2|\.ddd|\.deb|\.def|\.deploy|\.der|\.dfac|\.dgc|\.dic|\.dir|\.dis|\.dist|\.distz|\.djv|\.djvu|\.dll|\.dmg|\.dmp|\.dms|\.dna|\.doc|\.docm|\.docx|\.dot|\.dotm|\.dotx|\.dp|\.dpg|\.dra|\.dsc|\.dssc|\.dtb|\.dtd|\.dts|\.dtshd|\.dump|\.dvb|\.dvi|\.dwf|\.dwg|\.dxf|\.dxp|\.dxr|\.ecelp4800|\.ecelp7470|\.ecelp9600|\.ecma|\.edm|\.edx|\.efif|\.ei6|\.elc|\.emf|\.eml|\.emma|\.emz|\.eol|\.eot|\.eps|\.epub|\.es3|\.esa|\.esf|\.et3|\.etx|\.eva|\.evy|\.exe|\.exi|\.ext|\.ez|\.ez2|\.ez3|\.f|\.f4v|\.f77|\.f90|\.fbs|\.fcdt|\.fcs|\.fdf|\.fe_launch|\.fg5|\.fgd|\.fh|\.fh4|\.fh5|\.fh7|\.fhc|\.fig|\.flac|\.fli|\.flo|\.flv|\.flw|\.flx|\.fly|\.fm|\.fnc|\.for|\.fpx|\.frame|\.fsc|\.fst|\.ftc|\.fti|\.fvt|\.fxp|\.fxpl|\.fzs|\.g2w|\.g3|\.g3w|\.gac|\.gam|\.gbr|\.gca|\.gdl|\.geo|\.gex|\.ggb|\.ggs|\.ggt|\.ghf|\.gif|\.gim|\.gml|\.gmx|\.gnumeric|\.go|\.gph|\.gpx|\.gqf|\.gqs|\.gram|\.gramps|\.gre|\.grv|\.grxml|\.gsf|\.gtar|\.gtm|\.gtw|\.gv|\.gxf|\.gxt|\.gz|\.h|\.h261|\.h263|\.h264|\.hal|\.hbci|\.hdf|\.hh|\.hlp|\.hpgl|\.hpid|\.hps|\.hqx|\.htke|\.htm|\.html|\.hvd|\.hvp|\.hvs|\.i2g|\.icc|\.ice|\.icm|\.ico|\.ics|\.ief|\.ifb|\.ifm|\.iges|\.igl|\.igm|\.igs|\.igx|\.iif|\.imp|\.ims|\.in|\.ink|\.inkml|\.install|\.iota|\.ipfix|\.ipk|\.irm|\.irp|\.iso|\.itp|\.ivp|\.ivu|\.jad|\.jam|\.jar|\.java|\.jisp|\.jlt|\.jnlp|\.joda|\.jpe|\.jpeg|\.jpg|\.jpgm|\.jpgv|\.jpm|\.js|\.jsonml|\.kar|\.karbon|\.kfo|\.kia|\.kml|\.kmz|\.kne|\.knp|\.kon|\.kpr|\.kpt|\.kpxx|\.ksp|\.ktr|\.ktx|\.ktz|\.kwd|\.kwt|\.lasxml|\.latex|\.lbd|\.lbe|\.les|\.lha|\.link66|\.list|\.list3820|\.listafp|\.lnk|\.log|\.lostxml|\.lrf|\.lrm|\.ltf|\.lvp|\.lwp|\.lzh|\.m13|\.m14|\.m1v|\.m21|\.m2a|\.m2t|\.m2ts|\.m2v|\.m3a|\.m3u|\.m3u8|\.m4a|\.m4u|\.m4v|\.ma|\.mads|\.mag|\.maker|\.man|\.mar|\.mathml|\.mb|\.mbk|\.mbox|\.mc1|\.mcd|\.mcurl|\.md|\.mdb|\.mdi|\.me|\.mesh|\.meta4|\.metalink|\.mets|\.mfm|\.mft|\.mgp|\.mgz|\.mid|\.midi|\.mie|\.mif|\.mime|\.mj2|\.mjp2|\.mjs|\.mk3d|\.mka|\.mks|\.mkv|\.mlp|\.mmd|\.mmf|\.mmr|\.mng|\.mny|\.mobi|\.mods|\.mov|\.movie|\.mp2|\.mp21|\.mp2a|\.mp3|\.mp4|\.mp4a|\.mp4s|\.mp4v|\.mpc|\.mpe|\.mpeg|\.mpg|\.mpg4|\.mpga|\.mpkg|\.mpm|\.mpn|\.mpp|\.mpt|\.mpy|\.mqy|\.mrc|\.mrcx|\.ms|\.mscml|\.mseed|\.mseq|\.msf|\.msh|\.msi|\.msl|\.msty|\.mts|\.mus|\.musicxml|\.mvb|\.mwf|\.mxf|\.mxl|\.mxml|\.mxs|\.mxu|\.n-gage|\.n3|\.nb|\.nbp|\.nc|\.ncx|\.nfo|\.ngdat|\.nitf|\.nlu|\.nml|\.nnd|\.nns|\.nnw|\.npx|\.nsc|\.nsf|\.ntf|\.nzb|\.o|\.oa2|\.oa3|\.oas|\.obd|\.obj|\.oda|\.odb|\.odc|\.odf|\.odft|\.odg|\.odi|\.odm|\.odp|\.ods|\.odt|\.oga|\.ogg|\.ogv|\.ogx|\.omdoc|\.onepkg|\.onetmp|\.onetoc|\.onetoc2|\.opf|\.opml|\.oprc|\.opus|\.org|\.osf|\.osfpvg|\.otc|\.otf|\.otg|\.oth|\.oti|\.otp|\.ots|\.ott|\.oxps|\.oxt|\.p|\.p10|\.p12|\.p7b|\.p7c|\.p7m|\.p7r|\.p7s|\.p8|\.pas|\.paw|\.pbd|\.pbm|\.pcap|\.pcf|\.pcl|\.pclxl|\.pct|\.pcurl|\.pcx|\.pdb|\.pdf|\.pfa|\.pfb|\.pfm|\.pfr|\.pfx|\.pgm|\.pgn|\.pgp|\.pic|\.pkg|\.pki|\.pkipath|\.plb|\.plc|\.plf|\.pls|\.pml|\.png|\.pnm|\.portpkg|\.pot|\.potm|\.potx|\.ppam|\.ppd|\.ppm|\.pps|\.ppsm|\.ppsx|\.ppt|\.pptm|\.pptx|\.pqa|\.prc|\.pre|\.prf|\.ps|\.psb|\.psd|\.psf|\.pskcxml|\.ptid|\.pub|\.pvb|\.pwn|\.py|\.pya|\.pyv|\.qam|\.qbo|\.qfx|\.qps|\.qt|\.qwd|\.qwt|\.qxb|\.qxd|\.qxl|\.qxt|\.ra|\.ram|\.rar|\.ras|\.rcprofile|\.rdz|\.rep|\.res|\.rgb|\.rif|\.rip|\.ris|\.rl|\.rlc|\.rld|\.rm|\.rmi|\.rmp|\.rms|\.rmvb|\.rnc|\.roa|\.roff|\.rp9|\.rpss|\.rpst|\.rq|\.rs|\.rsd|\.rss|\.rtf|\.rtx|\.s|\.s3m|\.saf|\.sbml|\.sc|\.scd|\.scm|\.scq|\.scs|\.scurl|\.sda|\.sdc|\.sdd|\.sdkd|\.sdkm|\.sdp|\.sdw|\.see|\.seed|\.sema|\.semd|\.semf|\.ser|\.setpay|\.setreg|\.sfd-hdstx|\.sfs|\.sfv|\.sgi|\.sgl|\.sgm|\.sgml|\.sh|\.shar|\.shf|\.sid|\.sig|\.sil|\.silo|\.sis|\.sisx|\.sit|\.sitx|\.skd|\.skm|\.skp|\.skt|\.sldm|\.sldx|\.slt|\.sm|\.smf|\.smi|\.smil|\.smv|\.smzip|\.snd|\.snf|\.so|\.spc|\.spf|\.spl|\.spot|\.spp|\.spq|\.spx|\.sql|\.src|\.srt|\.sru|\.srx|\.ssdl|\.sse|\.ssf|\.ssml|\.st|\.stc|\.std|\.stf|\.sti|\.stk|\.stl|\.str|\.stw|\.sub|\.sus|\.susp|\.sv4cpio|\.sv4crc|\.svc|\.svd|\.svg|\.svgz|\.swa|\.swf|\.swi|\.sxc|\.sxd|\.sxg|\.sxi|\.sxm|\.sxw|\.t|\.t3|\.taglet|\.tao|\.tar|\.tcap|\.tcl|\.teacher|\.tei|\.teicorpus|\.tex|\.texi|\.texinfo|\.text|\.tfi|\.tfm|\.tga|\.thmx|\.tif|\.tiff|\.tmo|\.torrent|\.tpl|\.tpt|\.tr|\.tra|\.trm|\.ts|\.tsd|\.tsv|\.ttc|\.ttf|\.ttl|\.twd|\.twds|\.txd|\.txf|\.u32|\.udeb|\.ufd|\.ufdl|\.ulx|\.umj|\.unityweb|\.uoml|\.uri|\.uris|\.urls|\.ustar|\.utz|\.uu|\.uva|\.uvd|\.uvf|\.uvg|\.uvh|\.uvi|\.uvm|\.uvp|\.uvs|\.uvt|\.uvu|\.uvv|\.uvva|\.uvvd|\.uvvf|\.uvvg|\.uvvh|\.uvvi|\.uvvm|\.uvvp|\.uvvs|\.uvvt|\.uvvu|\.uvvv|\.uvvx|\.uvvz|\.uvx|\.uvz|\.vcard|\.vcd|\.vcf|\.vcg|\.vcs|\.vcx|\.vis|\.viv|\.vob|\.vor|\.vox|\.vrml|\.vsd|\.vsf|\.vss|\.vst|\.vsw|\.vtu|\.vxml|\.w3d|\.wad|\.wasm|\.wav|\.wax|\.wbmp|\.wbs|\.wbxml|\.wcm|\.wdb|\.wdp|\.weba|\.webm|\.webp|\.wg|\.wgt|\.wks|\.wm|\.wma|\.wmd|\.wmf|\.wml|\.wmlc|\.wmls|\.wmlsc|\.wmv|\.wmx|\.wmz|\.woff|\.woff2|\.wpd|\.wpl|\.wps|\.wqd|\.wri|\.wrl|\.wsdl|\.wspolicy|\.wtb|\.wvx|\.x32|\.x3d|\.x3db|\.x3dbz|\.x3dv|\.x3dvz|\.x3dz|\.xaml|\.xap|\.xar|\.xbap|\.xbd|\.xbm|\.xdf|\.xdm|\.xdp|\.xdssc|\.xdw|\.xenc|\.xer|\.xfdf|\.xfdl|\.xht|\.xhtml|\.xhvml|\.xif|\.xla|\.xlam|\.xlc|\.xlf|\.xlm|\.xls|\.xlsb|\.xlsm|\.xlsx|\.xlt|\.xltm|\.xltx|\.xlw|\.xm|\.xo|\.xop|\.xpi|\.xpl|\.xpm|\.xpr|\.xps|\.xpw|\.xpx|\.xsl|\.xslt|\.xsm|\.xspf|\.xul|\.xvm|\.xvml|\.xwd|\.xyz|\.xz|\.yang|\.yin|\.z1|\.z2|\.z3|\.z4|\.z5|\.z6|\.z7|\.z8|\.zaz|\.zip|\.zir|\.zirz|\.zmm)$'
]

SBOM_WHITELIST_EXTENSIONS = [
    r'^.*(\.sbom|\.bom|\.cdx|\.spdx|\.json|\.rdf|\.xml|\.yaml|\.yml)$',
    r'^.*(\.txt|\.cyclonedx|\.yml|\.tag|\.spdxjson|\.spdx-json|\.tv|\.dat)$',
]

SBOM_NAME_WHITELIST_NO_EXTENSIONS = [
    r'^.*(bom|dx).*$',
]

# SPDX SECTION
SPDX_YAML_FILTERS = [
    r'spdxVersion *: *(\"|)SPDX-',
    r'SPDXID *: *(\"|)SPDXRef-DOCUMENT'
]
SPDX_YAML_FILE_FILTERS = [
    r'^.*(\.yaml|\.yml)$'
]

SPDX_JSON_FILTERS = [
    r'\"SPDXVersion\" *: *\"SPDX-',
    r'\"SPDXID\" *: *\"SPDXRef-DOCUMENT\"'
]
SPDX_JSON_FILE_FILTERS = [
    r'^.*(\.json|\.spdxjson|\.spdx-json)$'
]

SPDX_XML_FILTERS = [
    r'<SPDXID> *SPDXRef-DOCUMENT *<\/SPDXID>',
]
SPDX_XML_FILE_FILTERS = [
    r'^.*(\.xml)$'
]

SPDX_RDF_FILTERS = [
    r'xmlns:spdx *= *(\"|)http(s|):\/\/spdx\.org\/rdf\/'
]
SPDX_RDF_FILE_FILTERS = [
    r'^.*(\.rdf|\.xml)$'
]

SPDX_SPDX_FILTERS = [
    r'SPDXVersion(\"|\'|) *: *(\"|\'|)SPDX-',
    r'SPDXID(\"|\'|) *: *(\"|\'|)SPDXRef-DOCUMENT',
]
SPDX_SPDX_AND_FILTERS = [
    r'Relationship(\"|\'|) *:'
]
SPDX_SPDX_FILE_FILTERS = [
    r'^.*(\.spdx|(\.|)license|\.tag)$'
]

SPDX_3_FILTERS = [
    r'\@context(\"|\'|) *: *(\"|\'|)http(s|):\/\/spdx\.org\/rdf\/'
]
SPDX_3_FILE_FILTERS = [
    r'^.*$'
]

SPDX_GENERIC_FILTERS = SPDX_SPDX_FILTERS
SPDX_GENERIC_FILTERS += SPDX_3_FILTERS
SPDX_GENERIC_FILE_FILTERS = [
#    r'^.*(\.sbom|\.bom)$'
    r'^.*$'
]

# CYCLONEDX SECTION
CYCLONEDX_XML_FILTERS = [
    r'xmlns *= *(\"|)http(s|):\/\/cyclonedx\.org\/schema\/bom\/'
]
CYCLONEDX_XML_FILE_FILTERS = [
    #r'^.*(\.xml|\.bom|\.sbom|\.cdx)$'
    r'^.*$'
]


CYCLONEDX_JSON_FILTERS = [
    r'\"bomFormat\" *: *\"CycloneDX\"'
]
CYCLONEDX_JSON_FILE_FILTERS = [
#    r'^.*(\.json|\.bom|\.sbom|\.cdx)$'
    r'^.*$'
]

# Languages_according_to_TIOBE
TOP_20_LANGUAGES = [
    'Python', 'C++', 'Java', 'C', 'C#', 'JavaScript', 'VBA', 'VBScript', 'Go', 'SQL', 'Fortran',
    'Pascal', 'MATLAB', 'PHP', 'Rust', 'R', 'Ruby', 'Kotlin', 'COBOL', 'Swift'
]
GITHUB_POPULAR_LANGUAGES = [
    'C', 'C#', 'C++', 'CoffeeScript', 'CSS', 'Dart', 'DM', 'Go', 'Groovy', 'HTML', 'Java', 'JavaScript',
    'Kotlin', 'Objective-C', 'Perl', 'PHP', 'PowerShell', 'Python', 'Ruby', 'Rust', 'Scala', 'Shell', 'Swift',
    'TypeScript'
]

ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tgz", ".7z", ".rar", ".gz", ".xz"]

def get_latest_data_folder(folder: str) -> str:
    # find the latest 'data_*' folder
    data_folders = [f for f in os.listdir(folder) if os.path.isdir(os.path.join(folder, f)) and f[:5] == 'data_']
    data_folders.sort(reverse=True)
    if len(data_folders) == 0:
        print("No data folders found.")
        return ''
    return str(os.path.join(folder, data_folders[0]))

def get_all_data_folders(folder: str) -> list[str]:
    # find the latest 'data_*' folder
    data_folders = [f for f in os.listdir(folder) if os.path.isdir(os.path.join(folder, f)) and f[:5] == 'data_']
    data_folders.sort(reverse=True)
    if len(data_folders) == 0:
        print("No data folders found.")
        return []
    return data_folders

def get_folder_size(folder: str) -> int:
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total_size += os.path.getsize(fp)
            except FileNotFoundError:
                continue
    return total_size

def random_string(length: int) -> str:
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

async def unpack_archive(archive_path:str, unpacked_dir:str) -> bool:
    # get current unpack formats
    # add 7zip to the list of unpack formats
    # if 7zip is not in the list
    unpack_formats = await aioshutil.get_unpack_formats()
    if '7zip' not in [unpack_format[0] for unpack_format in unpack_formats]:
        # register shutil.unpack_archive function for 7zip archives
        await aioshutil.register_unpack_format('7zip', ['.7z'], unpack_7zarchive)

    # check if the asset is an archive
    archive_name = os.path.basename(archive_path)
    if archive_name.endswith(tuple(ARCHIVE_EXTENSIONS)):
        try:
            extension: str = archive_name.split('.')[-1]
            if extension.lower() == 'rar':
                patoolib.extract_archive(archive_path, outdir=unpacked_dir, verbosity=-1, interactive=False)
            else:
                await aioshutil.unpack_archive(archive_path, unpacked_dir)
        except ReadError:
            try:
                unpacked = False
                if zipfile.is_zipfile(archive_path):
                    with ZipFile(archive_path, 'r') as zip_ref:
                        zip_ref.extractall(unpacked_dir)
                        unpacked = True
                if tarfile.is_tarfile(archive_path):
                    with tarfile.open(archive_path, 'r') as tar_ref:
                        tar_ref.extractall(unpacked_dir)
                        unpacked = True
                if not unpacked:
                    print(f"Could not extract the archive: {archive_path}")
                    if not os.path.exists(unpacked_dir):
                        return False
            except Exception as e:
                print(f"Error: {e}")
                print(f"Could not extract the archive: {archive_path}")
                if not os.path.exists(unpacked_dir):
                    return False
        except UnsupportedCompressionMethodError as e:
            if "py7zr" in e.args[1]:
                # check if unpacked_dir exists
                # because sometimes this tool can extract at least some data
                if not os.path.exists(unpacked_dir):
                    return False
        except Exception as e:
            print(f"Error: {e}")
            print(f"Could not extract the archive: {archive_path}")
            if not os.path.exists(unpacked_dir):
                return False
        # check if unpacked_dir exists
        # because some archives may be empty
        if not os.path.exists(unpacked_dir):
            return False
        return True
    return False


def NOT_SBOM_EXTENSIONS():
    return None