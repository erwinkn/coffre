// The composite action runs exactly one pinned CLI. Fail closed if its
// command changes shape, rather than silently leaving a release's pin behind.
export function actionPin(text) {
    const matches = [...text.matchAll(/\bnpx -y @coffre\/cli@([^\s]+)/g)];
    if (matches.length !== 1 || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(matches[0][1])) {
        throw new Error('action/action.yml must run exactly one npx -y @coffre/cli@<exact version>');
    }
    return matches[0][1];
}

export function bumpAction(text, version) {
    const before = actionPin(text);
    return text.replace(`npx -y @coffre/cli@${before}`, `npx -y @coffre/cli@${version}`);
}
