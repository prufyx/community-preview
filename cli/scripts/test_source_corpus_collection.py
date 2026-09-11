from __future__ import annotations
import copy, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
SCRIPT = Path(__file__).with_name("source_corpus_collection.py")
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("source_corpus_collection", SCRIPT)
assert spec and spec.loader
collection = importlib.util.module_from_spec(spec); spec.loader.exec_module(collection)
EXAMPLE = SCRIPT.parents[1] / "examples" / "source-corpus-collection"
class CollectionTests(unittest.TestCase):
    def tree(self):
        holder = tempfile.TemporaryDirectory(); root = (Path(holder.name) / "collection").resolve(); shutil.copytree(EXAMPLE, root)
        for item in root.rglob("*"): item.chmod(0o700 if item.is_dir() else 0o600)
        root.chmod(0o700); return holder, root
    def verify(self, root): return collection.verify_collection_paths(root, "collection-index.json")
    def load_manifest(self, root, shard): return json.loads((root / shard / "manifest.json").read_text())
    def save_manifest(self, root, shard, value):
        path = root / shard / "manifest.json"; path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n"); path.chmod(0o600)
    def test_two_shards_deduplicate_and_repeat_deterministically(self):
        holder, root = self.tree()
        try:
            first, second = self.verify(root), self.verify(root)
            self.assertEqual(collection.corpus._canonical(first), collection.corpus._canonical(second)); self.assertEqual((first["recordCount"], first["projectCount"], first["uniqueObjectCount"], first["aggregateByteLength"]), (2, 2, 1, 52)); self.assertEqual(first["verification"], "VERIFIED_LOCAL_COLLECTION"); self.assertIn("does not approve catalogue identity", " ".join(first["limitations"]))
            expected = collection.corpus.verify_corpus(self.load_manifest(root, "shard-a"), root / "shard-a" / "objects")
            self.assertEqual(first["shardReceipts"][0]["receiptDigest"], "sha256:" + hashlib.sha256(collection.corpus._canonical(expected)).hexdigest())
        finally: holder.cleanup()
    def test_rejects_index_schema_paths_order_and_duplicates(self):
        cases = [lambda x: x.__setitem__("extra", True), lambda x: x.__setitem__("shards", list(reversed(x["shards"]))), lambda x: x["shards"][0].__setitem__("manifestPath", "../canary"), lambda x: x["shards"][0].__setitem__("objectRoot", "shard-a//objects"), lambda x: x["shards"].append(copy.deepcopy(x["shards"][0]))]
        for mutate in cases:
            holder, root = self.tree()
            try:
                index = json.loads((root / "collection-index.json").read_text()); mutate(index); p = root / "collection-index.json"; p.write_text(json.dumps(index, sort_keys=True) + "\n"); p.chmod(0o600)
                with self.assertRaises(collection.CollectionError): self.verify(root)
            finally: holder.cleanup()
    def test_rejects_duplicate_index_json_keys_and_non_private_root(self):
        holder, root = self.tree()
        try:
            path = root / "collection-index.json"
            path.write_bytes(b'{"schema":"prufyx.io/private-source-corpus-collection/v1","schema":"duplicate","revision":"collection-v1","authority":"LOCAL_VERIFIED_RETAINED_SHARDS_NOT_RULE_OR_RUNTIME_PROOF","shards":[]}')
            path.chmod(0o600)
            with self.assertRaises(collection.CollectionError): self.verify(root)
        finally: holder.cleanup()
    def test_rejects_index_utf8_depth_and_path_bounds(self):
        index = {"schema": "prufyx.io/private-source-corpus-collection/v1", "revision": "collection-v1", "authority": "LOCAL_VERIFIED_RETAINED_SHARDS_NOT_RULE_OR_RUNTIME_PROOF", "shards": [{"manifestPath": "a/manifest.json", "objectRoot": "a/objects"}]}
        for raw in (b"\x80", json.dumps({**index, "shards": [{"manifestPath": "a/" + ("x" * 600), "objectRoot": "a/objects"}]}).encode(), json.dumps({**index, "shards": [{"manifestPath": "/".join(["a"] * 17), "objectRoot": "a/objects"}]}).encode()):
            with self.assertRaises(collection.CollectionError): collection._parse_index(raw)
        holder, root = self.tree()
        try:
            root.chmod(0o755)
            with self.assertRaises(collection.CollectionError): self.verify(root)
        finally: holder.cleanup()
    def test_rejects_cross_shard_duplicate_and_conflicting_identity(self):
        cases = [lambda second, first: second["records"][0].__setitem__("id", first["records"][0]["id"]), lambda second, first: (second["records"][0]["project"].update(first["records"][0]["project"]), second["records"][0]["source"].update({"repositoryURL": first["records"][0]["source"]["repositoryURL"], "immutableURL": first["records"][0]["source"]["immutableURL"], "commit": first["records"][0]["source"]["commit"]})), lambda second, first: second["records"][0]["project"].__setitem__("slug", first["records"][0]["project"]["slug"]), lambda second, first: second["records"][0]["source"].update({"repositoryURL": first["records"][0]["source"]["repositoryURL"], "immutableURL": first["records"][0]["source"]["immutableURL"], "commit": first["records"][0]["source"]["commit"]})]
        for mutate in cases:
            holder, root = self.tree()
            try:
                first, second = self.load_manifest(root, "shard-a"), self.load_manifest(root, "shard-b"); mutate(second, first); self.save_manifest(root, "shard-b", second)
                with self.assertRaises(collection.CollectionError): self.verify(root)
            finally: holder.cleanup()
    def test_allows_distinct_spans_for_same_immutable_source_but_rejects_metadata_conflict(self):
        holder, root = self.tree()
        try:
            first, second = self.load_manifest(root, "shard-a"), self.load_manifest(root, "shard-b")
            first_record, second_record = first["records"][0], second["records"][0]
            second_record["source"]["repositoryURL"] = first_record["source"]["repositoryURL"]
            second_record["source"]["immutableURL"] = first_record["source"]["immutableURL"]
            second_record["source"]["commit"] = first_record["source"]["commit"]
            second_record["source"]["version"] = first_record["source"]["version"]
            second_record["source"]["spans"] = [{"startLine": 2, "endLine": 2, "spanDigest": "sha256:" + hashlib.sha256(b"setting removed in v1.0.0").hexdigest()}]
            self.save_manifest(root, "shard-b", second)
            self.assertEqual(self.verify(root)["recordCount"], 2)
            second_record["source"]["sourceKind"] = "changelog"
            self.save_manifest(root, "shard-b", second)
            with self.assertRaises(collection.CollectionError): self.verify(root)
        finally: holder.cleanup()
    def test_rejects_non_private_modes_links_hardlinks_and_fifo(self):
        holder, root = self.tree()
        try:
            (root / "shard-a" / "manifest.json").chmod(0o644)
            with self.assertRaises(collection.CollectionError): self.verify(root)
        finally: holder.cleanup()
        holder, root = self.tree()
        try:
            item = next((root / "shard-a" / "objects" / "sha256").iterdir()); saved = item.with_name("saved"); item.rename(saved); item.symlink_to(saved.name)
            with self.assertRaises(collection.CollectionError): self.verify(root)
        finally: holder.cleanup()
        holder, root = self.tree()
        try:
            item = next((root / "shard-a" / "objects" / "sha256").iterdir()); os.link(item, item.with_name("hardlink"))
            with self.assertRaises(collection.CollectionError): self.verify(root)
        finally: holder.cleanup()
        if hasattr(os, "mkfifo"):
            holder, root = self.tree()
            try:
                item = next((root / "shard-a" / "objects" / "sha256").iterdir()); item.unlink(); os.mkfifo(item)
                with self.assertRaises(collection.CollectionError): self.verify(root)
            finally: holder.cleanup()
        holder, root = self.tree()
        try:
            objects = root / "shard-a" / "objects"; saved = objects.with_name("objects-saved"); objects.rename(saved); objects.symlink_to(saved.name)
            with self.assertRaises(collection.CollectionError): self.verify(root)
        finally: holder.cleanup()
        holder, root = self.tree()
        try:
            (root / "shard-a" / "objects" / "sha256").chmod(0o755)
            with self.assertRaises(collection.CollectionError): self.verify(root)
        finally: holder.cleanup()
    def test_rejection_paths_close_root_and_object_directory_descriptors(self):
        def fd_count():
            return len(os.listdir("/dev/fd"))
        holder, root = self.tree()
        try:
            root.chmod(0o755); before = fd_count()
            for _ in range(8):
                with self.assertRaises(collection.CollectionError): collection._open_root(root)
            self.assertEqual(fd_count(), before)
        finally: holder.cleanup()
        holder, root = self.tree()
        try:
            sha = root / "shard-a" / "objects" / "sha256"; sha.chmod(0o755); root_fd = collection._open_root(root); before = fd_count()
            for _ in range(8):
                with self.assertRaises(collection.CollectionError): collection._object_reader(root_fd, "shard-a/objects")
            self.assertEqual(fd_count(), before); os.close(root_fd); root_fd = -1
        finally:
            if 'root_fd' in locals() and root_fd >= 0: os.close(root_fd)
            holder.cleanup()
    def test_reader_holds_descriptor_when_path_replaced(self):
        holder, root = self.tree(); root_fd = -1; descriptors = ()
        try:
            root_fd = collection._open_root(root); reader, descriptors = collection._object_reader(root_fd, "shard-a/objects"); item = next((root / "shard-a" / "objects" / "sha256").iterdir()); saved = item.with_name("replacement-source"); real_open, replaced = collection.os.open, False
            def hooked(path, flags, *args, **kwargs):
                nonlocal replaced
                fd = real_open(path, flags, *args, **kwargs)
                if path == item.name and kwargs.get("dir_fd") == descriptors[1] and not replaced: item.rename(saved); item.symlink_to(saved.name); replaced = True
                return fd
            collection.os.open = hooked
            try: data = reader("sha256/" + item.name)
            finally: collection.os.open = real_open
            self.assertTrue(replaced); self.assertEqual(data, saved.read_bytes())
        finally:
            for fd in descriptors:
                if fd >= 0: os.close(fd)
            if root_fd >= 0: os.close(root_fd)
            holder.cleanup()
    def test_collection_cap_boundaries_use_two_shard_fixture(self):
        holder, root = self.tree()
        original = {name: getattr(collection, name) for name in ("MAX_SHARDS", "MAX_RECORDS", "MAX_OBJECTS", "MAX_UNIQUE_BYTES", "MAX_OUTPUT_BYTES", "MAX_INDEX_BYTES")}
        try:
            baseline = self.verify(root)
            index_raw = (root / "collection-index.json").read_bytes()
            output_bytes = len(collection.corpus._canonical(baseline) + b"\n")
            thresholds = {
                "MAX_SHARDS": 2,
                "MAX_RECORDS": baseline["recordCount"],
                "MAX_OBJECTS": baseline["uniqueObjectCount"],
                "MAX_UNIQUE_BYTES": baseline["aggregateByteLength"],
                "MAX_OUTPUT_BYTES": output_bytes,
                "MAX_INDEX_BYTES": len(index_raw),
            }
            for name, threshold in thresholds.items():
                with self.subTest(cap=name, boundary="exact"):
                    setattr(collection, name, threshold)
                    if name == "MAX_INDEX_BYTES":
                        self.assertEqual(collection._parse_index(index_raw)["revision"], "collection-v1")
                    else:
                        self.assertEqual(self.verify(root)["verification"], "VERIFIED_LOCAL_COLLECTION")
                with self.subTest(cap=name, boundary="below"):
                    setattr(collection, name, threshold - 1)
                    with self.assertRaises(collection.CollectionError):
                        if name == "MAX_INDEX_BYTES": collection._parse_index(index_raw)
                        else: self.verify(root)
                setattr(collection, name, original[name])
        finally:
            for name, value in original.items(): setattr(collection, name, value)
            holder.cleanup()

    def test_cli_success_is_canonical_and_errors_do_not_echo_canary(self):
        holder, root = self.tree()
        try:
            command = ["python3", "-B", str(SCRIPT), "verify", "--root", str(root), "--index", "collection-index.json"]; ok = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False); self.assertEqual(ok.returncode, 0); self.assertEqual(ok.stdout[-1:], b"\n"); self.assertEqual(json.loads(ok.stdout)["recordCount"], 2)
            bad = subprocess.run([*command[:-1], "CANARY/private-index.json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False); self.assertEqual(bad.returncode, 2); self.assertEqual(bad.stdout, b""); self.assertNotIn(b"CANARY", bad.stderr); self.assertNotIn(str(root).encode(), bad.stderr)
        finally: holder.cleanup()
if __name__ == "__main__": unittest.main()
