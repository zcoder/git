#!/bin/sh

test_description='Test git check-ref-format'

. ./test-lib.sh

valid_ref() {
	if test "$#" = 1
	then
		test_expect_success "ref name '$1' is valid" \
			"git check-ref-format '$1'"
	else
		test_expect_success "ref name '$1' is valid with options $2" \
			"git check-ref-format $2 '$1'"
	fi
}
invalid_ref() {
	if test "$#" = 1
	then
		test_expect_success "ref name '$1' is invalid" \
			"test_must_fail git check-ref-format '$1'"
	else
		test_expect_success "ref name '$1' is invalid with options $2" \
			"test_must_fail git check-ref-format $2 '$1'"
	fi
}

invalid_ref ''
invalid_ref '/'
invalid_ref '/' --allow-onelevel
invalid_ref '/' --normalize
invalid_ref '/' '--allow-onelevel --normalize'
valid_ref 'foo/bar/baz'
valid_ref 'foo/bar/baz' --normalize
invalid_ref 'refs///heads/foo'
valid_ref 'refs///heads/foo' --normalize
invalid_ref 'heads/foo/'
invalid_ref '/heads/foo'
valid_ref '/heads/foo' --normalize
invalid_ref '///heads/foo'
valid_ref '///heads/foo' --normalize
invalid_ref './foo'
invalid_ref './foo/bar'
invalid_ref 'foo/./bar'
invalid_ref 'foo/bar/.'
invalid_ref '.refs/foo'
invalid_ref 'heads/foo..bar'
invalid_ref 'heads/foo?bar'
valid_ref 'foo./bar'
invalid_ref 'heads/foo.lock'
invalid_ref 'heads///foo.lock'
invalid_ref 'foo.lock/bar'
invalid_ref 'foo.lock///bar'
valid_ref 'heads/foo@bar'
invalid_ref 'heads/v@{ation'
invalid_ref 'heads/foo\bar'
invalid_ref "$(printf 'heads/foo\t')"
invalid_ref "$(printf 'heads/foo\177')"
valid_ref "$(printf 'heads/fu\303\237')"
invalid_ref 'heads/*foo/bar' --refspec-pattern
invalid_ref 'heads/foo*/bar' --refspec-pattern
invalid_ref 'heads/f*o/bar' --refspec-pattern

ref='foo'
invalid_ref "$ref"
valid_ref "$ref" --allow-onelevel
invalid_ref "$ref" --refspec-pattern
valid_ref "$ref" '--refspec-pattern --allow-onelevel'
invalid_ref "$ref" --normalize
valid_ref "$ref" '--allow-onelevel --normalize'

ref='foo/bar'
valid_ref "$ref"
valid_ref "$ref" --allow-onelevel
valid_ref "$ref" --refspec-pattern
valid_ref "$ref" '--refspec-pattern --allow-onelevel'
valid_ref "$ref" --normalize

ref='foo/*'
invalid_ref "$ref"
invalid_ref "$ref" --allow-onelevel
valid_ref "$ref" --refspec-pattern
valid_ref "$ref" '--refspec-pattern --allow-onelevel'

ref='*/foo'
invalid_ref "$ref"
invalid_ref "$ref" --allow-onelevel
valid_ref "$ref" --refspec-pattern
valid_ref "$ref" '--refspec-pattern --allow-onelevel'
invalid_ref "$ref" --normalize
valid_ref "$ref" '--refspec-pattern --normalize'

ref='foo/*/bar'
invalid_ref "$ref"
invalid_ref "$ref" --allow-onelevel
valid_ref "$ref" --refspec-pattern
valid_ref "$ref" '--refspec-pattern --allow-onelevel'

ref='*'
invalid_ref "$ref"
invalid_ref "$ref" --allow-onelevel
invalid_ref "$ref" --refspec-pattern
valid_ref "$ref" '--refspec-pattern --allow-onelevel'

ref='foo/*/*'
invalid_ref "$ref" --refspec-pattern
invalid_ref "$ref" '--refspec-pattern --allow-onelevel'

ref='*/foo/*'
invalid_ref "$ref" --refspec-pattern
invalid_ref "$ref" '--refspec-pattern --allow-onelevel'

ref='*/*/foo'
invalid_ref "$ref" --refspec-pattern
invalid_ref "$ref" '--refspec-pattern --allow-onelevel'

ref='/foo'
invalid_ref "$ref"
invalid_ref "$ref" --allow-onelevel
invalid_ref "$ref" --refspec-pattern
invalid_ref "$ref" '--refspec-pattern --allow-onelevel'
invalid_ref "$ref" --normalize
valid_ref "$ref" '--allow-onelevel --normalize'
invalid_ref "$ref" '--refspec-pattern --normalize'
valid_ref "$ref" '--refspec-pattern --allow-onelevel --normalize'

test_expect_success "check-ref-format --branch @{-1}" '
	T=$(git write-tree) &&
	sha1=$(echo A | git commit-tree $T) &&
	git update-ref refs/heads/master $sha1 &&
	git update-ref refs/remotes/origin/master $sha1 &&
	git checkout master &&
	git checkout origin/master &&
	git checkout master &&
	refname=$(git check-ref-format --branch @{-1}) &&
	test "$refname" = "$sha1" &&
	refname2=$(git check-ref-format --branch @{-2}) &&
	test "$refname2" = master'

test_expect_success 'check-ref-format --branch from subdir' '
	mkdir subdir &&

	T=$(git write-tree) &&
	sha1=$(echo A | git commit-tree $T) &&
	git update-ref refs/heads/master $sha1 &&
	git update-ref refs/remotes/origin/master $sha1 &&
	git checkout master &&
	git checkout origin/master &&
	git checkout master &&
	refname=$(
		cd subdir &&
		git check-ref-format --branch @{-1}
	) &&
	test "$refname" = "$sha1"
'

valid_ref_normalized() {
	test_expect_success "ref name '$1' simplifies to '$2'" "
		refname=\$(git check-ref-format --normalize '$1') &&
		test \"\$refname\" = '$2'"
}
invalid_ref_normalized() {
	test_expect_success "check-ref-format --normalize rejects '$1'" "
		test_must_fail git check-ref-format --normalize '$1'"
}

valid_ref_normalized 'heads/foo' 'heads/foo'
valid_ref_normalized 'refs///heads/foo' 'refs/heads/foo'
valid_ref_normalized '/heads/foo' 'heads/foo'
valid_ref_normalized '///heads/foo' 'heads/foo'
invalid_ref_normalized 'foo'
invalid_ref_normalized '/foo'
invalid_ref_normalized 'heads/foo/../bar'
invalid_ref_normalized 'heads/./foo'
invalid_ref_normalized 'heads\foo'
invalid_ref_normalized 'heads/foo.lock'
invalid_ref_normalized 'heads///foo.lock'
invalid_ref_normalized 'foo.lock/bar'
invalid_ref_normalized 'foo.lock///bar'

test_done
