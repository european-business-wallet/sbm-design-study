# SPDX-License-Identifier: MIT
"""The permitted envelope transformations are one set, stated in three places.

`schemas/evidence-ce.schema.json` enumerates what a CE may declare. The
Internet-Draft names the same set in its CE definition. The TS repeats it in
clause 7, and the TS is the conformance layer — what an assessor reads and an
implementer follows.

They had drifted. The TS listed "MLS re-encryption on an epoch change while a
message is queued" among the permitted transformations and required a CE for it,
while the I-D said the opposite in terms — an intermediary cannot transform the
E2EE envelope, an epoch change re-encrypts no queued message, the epoch-change CE
type is removed, and a sender's resubmission is a NEW submission — and the schema
admitted only `re-packaging` and `chunking`. Following the TS produced an act the
protocol forbids and the schema cannot represent, which is worse than an
ambiguity: it is a conformance document instructing an implementer to build
something that cannot be expressed.

A set stated in three places needs one check, not three readings. The schema is
the authority here because it is the machine-readable one; the two documents are
read for the same members and for the removed value's absence.
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
CE_SCHEMA = ROOT / "schemas" / "evidence-ce.schema.json"
ID = ROOT / "ietf" / "draft-sbm-mls-erd-00.md"
TS = ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md"

REMOVED = "epoch-change"          # the value the profile withdrew


def schema_transformations():
    node = json.loads(CE_SCHEMA.read_text(encoding="utf-8"))["properties"]["transformation"]
    return set(node["enum"])


def id_transformations():
    """The CE definition's own list, as the Internet-Draft writes it."""
    line = next(l for l in ID.read_text(encoding="utf-8").splitlines()
                if l.startswith("- **CE (Change-Indication Evidence)**"))
    inside = re.search(r"`transformation`\s*\((.*?)—", line).group(1)
    return set(re.findall(r"`([a-z-]+)`", inside))


def ts_clause():
    text = TS.read_text(encoding="utf-8")
    start = text.index("## 7 Change indication")
    return text[start:text.index("\n## ", start + 10)]


def ts_transformations(clause=None):
    """What clause 7 lists as permitted, read from its own parenthetical.

    Read in whatever form the clause writes them — emphasis stripped, the list
    split on commas and "and" — so that re-admitting a transformation in plain
    prose fails exactly as re-admitting it in bold would. The first draft of
    this reader matched only bold tokens, which is to say it matched only the
    sentence this pass had just written; against the reviewed revision it
    returned the empty set and two tests passed for the wrong reason.
    """
    clause = ts_clause() if clause is None else clause
    sentence = next(s for s in clause.split(". ") if "only permitted transformations" in s)
    # Anchored on the phrase the list follows: the clause's own heading carries
    # "(Article 44(1)(e))", and an unanchored parenthetical reader finds that.
    inside = re.search(r"envelope/metadata\s*\((.*?)\)", sentence).group(1)
    members = re.split(r",| and ", inside.replace("*", ""))
    return {" ".join(m.split()).lower() for m in members if m.strip()}


def test_the_three_surfaces_name_the_same_set():
    schema = schema_transformations()
    assert schema == {"re-packaging", "chunking"}, schema
    assert id_transformations() == schema
    assert ts_transformations() == schema


def test_the_removed_value_is_admitted_nowhere():
    """`epoch-change` was a CE type and is not one. The schema must not admit it,
    and neither document may list it among what is permitted."""
    assert REMOVED not in schema_transformations()
    assert REMOVED not in id_transformations()
    # In the TS the value was never written as a token: the clause said "MLS
    # re-encryption on an epoch change while a message is queued". A member
    # naming an epoch is the thing to refuse, however it is spelled.
    assert not [m for m in ts_transformations() if "epoch" in m], ts_transformations()


def test_the_ts_states_what_an_epoch_change_is_instead():
    """Removing the wrong sentence is half the fix: clause 7 has to say what a
    sender does after an epoch change, or an implementer reads the silence as
    latitude. The I-D's answer is a new submission, not a transformation."""
    clause = ts_clause()
    assert "epoch change re-encrypts no queued application message" in clause
    assert "new submission" in clause
    assert "cannot transform the end-to-end-encrypted envelope" in clause


def test_the_id_and_the_ts_agree_that_an_intermediary_cannot_transform_the_envelope():
    id_line = next(l for l in ID.read_text(encoding="utf-8").splitlines()
                   if "intermediary cannot transform the E2EE envelope" in l)
    assert "epoch change re-encrypts NO queued application message" in id_line
    assert "NEW submission chain" in id_line


def test_the_readers_are_not_fooled_by_a_reworded_sentence(tmp_path):
    """The check reads the clause's own list, so re-admitting the value in other
    words still fails: it is the SET that is compared, not a blacklist."""
    import shutil
    copy = tmp_path / "TS.md"
    shutil.copy(TS, copy)
    text = copy.read_text(encoding="utf-8")
    text = text.replace("(**re-packaging** and **chunking**)",
                        "(re-packaging, chunking and MLS re-encryption on an epoch change)")
    copy.write_text(text, encoding="utf-8")
    clause = copy.read_text(encoding="utf-8")
    clause = clause[clause.index("## 7 Change indication"):]
    readmitted = ts_transformations(clause)
    assert readmitted != schema_transformations(), readmitted
    assert [m for m in readmitted if "epoch" in m], readmitted
