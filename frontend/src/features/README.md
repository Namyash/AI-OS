# features

Feature modules that combine components with the wording and data of one area of the product.

- `conversation/`: the primary surface (an empty state that says the assistant is not available yet, and the message composer,
  which is disabled until a model exists).
- `model/`: what the UI says about the local model. Today the only state is "No model loaded".
