# Fixtures

**These are reconstructions, not samples.** They are written from published
descriptions of the campaign's artifacts and prove that each detector fires
on the SHAPE described and stays quiet on the clean and false-positive
shapes. They do not prove the detectors fire on any specific real file.

That proof is yours to run: `php bin/scan.php <path-to-an-infected-webroot>`
on a copy of a compromised install, then on the cleaned copy. Compare the
"By detector" line with what you know is there.

Stored as `.txt` so nothing here is executable by accident. The scanner is
told the intended name through the test, not the file name.
