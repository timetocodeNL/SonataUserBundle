# DO NOT EDIT THIS FILE!
#
# It's auto-generated by sonata-project/dev-kit package.

.PHONY: test docs

all:
	@echo "Please choose a task."

lint:
	composer validate
	find . -name '*.yml' -not -path './vendor/*' -not -path './Resources/public/vendor/*' | xargs yaml-lint
	find . \( -name '*.xml' -or -name '*.xliff' \) \
		-not -path './vendor/*' -not -path './Resources/public/vendor/*' -type f \
		-exec xmllint --encode UTF-8 --output '{}' --format '{}' \;
	git diff --exit-code

test:
	phpunit -c phpunit.xml.dist --coverage-clover build/logs/clover.xml

docs:
	cd docs && sphinx-build -W -b html -d _build/doctrees . _build/html
