from veridion.report import CommentRecord, select_comment_upsert


def test_select_comment_upsert_returns_none_when_no_existing_veridion_comment() -> None:
    comments = [
        CommentRecord(comment_id=1, author_login="alice", body="Looks good"),
        CommentRecord(comment_id=2, author_login="github-actions[bot]", body="Unrelated bot output"),
    ]

    assert select_comment_upsert(comments) is None


def test_select_comment_upsert_returns_latest_matching_bot_comment() -> None:
    comments = [
        CommentRecord(
            comment_id=10,
            author_login="github-actions[bot]",
            body="<!-- veridion:rdi:start -->\nold\n<!-- veridion:rdi:end -->",
        ),
        CommentRecord(
            comment_id=11,
            author_login="github-actions[bot]",
            body="<!-- veridion:rdi:start -->\nnew\n<!-- veridion:rdi:end -->",
        ),
        CommentRecord(comment_id=12, author_login="alice", body="human comment"),
    ]

    assert select_comment_upsert(comments) == 11
