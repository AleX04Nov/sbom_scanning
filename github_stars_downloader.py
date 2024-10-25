import json
import os

import github_stars


def main(data_folder='./', language='python', gh_token=None, max_size=1048576, start_stars=100):
    if not gh_token:
        with open("github_token", "r") as f:
            gh_token = f.read().strip()
    gh = github_stars.GitHubStars(gh_token, start=start_stars)
    gh.search_query(language=language, max_size=max_size)
    print("----planning----")
    plan = []
    plan += gh.make_plan()
    print(f"----plan (≈{len(plan) * 20} requests)----")
    repos = gh.fetch(plan)
    print(f"----writing {len(repos)} repositories----")
    out_file = os.path.join(data_folder, f"top_repos_{language}")
    json_repos = [(repo.html_url, repo.stargazers_count, int(repo.created_at.timestamp())) for repo in repos]
    with open(out_file, "w") as fout:
        json.dump(json_repos, fout, indent=4, sort_keys=True)
    print(f"The result was written to {out_file}")
    return out_file

if __name__ == "__main__":
    main()
