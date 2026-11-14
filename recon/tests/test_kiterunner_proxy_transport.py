"""Kiterunner supply-chain regressions; native transport has a separate lab."""
import hashlib
import importlib.util
import io
import tarfile
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[1] / 'helpers/resource_enum/kiterunner_proxy'
spec = importlib.util.spec_from_file_location('kr_safe_tar_fixture', ROOT / 'tar_safe.py')
assert spec is not None and spec.loader is not None
safe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safe)

def _tar(member):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as tf:
        tf.addfile(member,io.BytesIO(b'x') if member.isfile() else None)
    stream.seek(0)
    return tarfile.open(fileobj=stream,mode='r:')

@pytest.mark.parametrize('name,kind,link',[
 ('../outside',tarfile.REGTYPE,''),('/absolute',tarfile.REGTYPE,''),
 ('link',tarfile.SYMTYPE,'../outside'),('link',tarfile.LNKTYPE,'../outside'),
 ('safe-link',tarfile.SYMTYPE,'inside'),('fifo',tarfile.FIFOTYPE,''),
 ('back\\slash',tarfile.REGTYPE,'')])
def test_archive_escape_and_links_are_rejected(tmp_path,name,kind,link):
    m=tarfile.TarInfo(name);m.type=kind;m.linkname=link;m.size=int(m.isfile())
    with _tar(m) as tf, pytest.raises(safe.UnsafeArchiveError): safe.safe_extract_tar(tf,tmp_path/'out')
    assert not (tmp_path/'outside').exists()

def test_regular_archive_and_preexisting_symlink(tmp_path):
    m=tarfile.TarInfo('nested/file');m.size=1
    with _tar(m) as tf:safe.safe_extract_tar(tf,tmp_path/'valid')
    assert (tmp_path/'valid/nested/file').read_bytes()==b'x'
    (tmp_path/'out').mkdir();(tmp_path/'out/nested').symlink_to(tmp_path/'valid')
    with _tar(m) as tf,pytest.raises(safe.UnsafeArchiveError): safe.safe_extract_tar(tf,tmp_path/'out')

def test_release_hash_is_verified_before_write(tmp_path):
    import sys
    with patch.dict(sys.modules,{'tar_safe':safe}):
        spec=importlib.util.spec_from_file_location('kr_build_fixture',ROOT/'build.py')
        assert spec is not None and spec.loader is not None
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    payload=b'x'*2048
    class Response(io.BytesIO):
        def __enter__(self):return self
        def __exit__(self,*args):self.close()
    with patch.object(mod.urllib.request,'urlopen',return_value=Response(payload)):
        with pytest.raises(RuntimeError,match='sha256 mismatch'):mod.download('https://fixture.test',tmp_path/'archive','0'*64)
    assert not (tmp_path/'archive').exists()
    assert mod.RELEASE_SHA256=='d553ed6a063b1a65bc72060be137b89d7c48f4da6ebf4fe46057807a5aa3d069'
