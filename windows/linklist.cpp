#include "linklist.h"  
#define NULL  0L

CLinkedList::CLinkedList()  // CLinkedList constructor  
{  
  pHead = pTail = pCurPosition = NULL;
}

CLinkedList::~CLinkedList()//  CLinkedList destructor - free each node  
{  
  LPNODE  pCur, pNext;  
  pCur = pHead;  
  pHead = pTail = pCurPosition = NULL;  
  // Go thru list and free each node  
  while (pCur != NULL)  
  {  
    pNext = pCur->pNext;  
    delete(pCur);  
    pCur = pNext;  
  }  
}

//  GetFirst - return app data for first entry in list and make it  
//  the current node.  
void  * CLinkedList::GetFirst()  
{  
  pCurPosition = pHead;  
  if (pCurPosition == NULL)  
  {  
    return(NULL);  
  }  
  return(pCurPosition->pData);  
}

// GetLast - return app data to last entry in list and make it  
//  the current node.  
void  * CLinkedList::GetLast()  
{  
//  pCurPosition = pTail;
  if (pTail == NULL)  
  {  
    return(NULL);  
  }  
  return(pTail->pData);  
}  
// GetNext - return next app data entry in list and make it  
//  the current node.  
void  * CLinkedList::GetNext()  
{  
  LPNODE  pNext;
  // check for empty list or already at end of list.  
  if ((pCurPosition == NULL) || (pCurPosition->pNext == NULL))  
  {  
    return(NULL);  
  }  
  pNext = pCurPosition->pNext;  
  pCurPosition = pNext;  
  return(pNext->pData);  
}  
//  GetFirst - return app data that follows a given entry and make it  
//  the current node.  
void  * CLinkedList::GetNext(void  *pData)  
{  
  pCurPosition = Find(pData);  
  return(GetNext());  
}  
// GetPrev - return app data for previous entry in list and make it  
//  the current node.  
void  * CLinkedList::GetPrev()  
{  
  LPNODE  pPrev;  
  // check for empty list or already at start  
  if ((pCurPosition == NULL) || (pCurPosition->pPrev == NULL))  
  {  
    return(NULL);  
  }  
  pPrev = pCurPosition->pPrev;  
  pCurPosition = pPrev;  
  return(pPrev->pData);  
   
}  
//  GetFirst - return app data that preceeds a given entry and make it  
//  the current node.  
void  * CLinkedList::GetPrev(void  *pData)  
{  
  pCurPosition = Find(pData);  
  return(GetPrev());  
}  
//  Add - create a new node and put it at the start of the list and  
// make it the current node.  
void CLinkedList::Add(void  *pData)  
{  
  LPNODE  pNew = new NODE;  
  // setup node and prepare it for its role as the new head of the list  
  pNew->pData = pData;  
  pNew->pNext = pHead;  
  pNew->pPrev = NULL;  
  // The old head of list (if any) should point to new node)  
  if (pHead != NULL)  
    pHead->pPrev = pNew;  
  // Make new node the head and current position  
  pHead = pNew;  
  pCurPosition = pNew;  
  // Check to see if new node is also the tail (ie. only list entry)  
  if (pTail == NULL)  
   pTail = pNew;  
}  
//  Append - create a new node and put it at the end of the list.  
void CLinkedList::Append(void  *pData)  
{  
  LPNODE  pNew = new NODE;  
  // setup node and prepare it for its role as the new tail of the list  
  pNew->pData = pData;  
  pNew->pPrev = pTail;  
  pNew->pNext = NULL;  
  // The old tail of list (if any) should point to new node.  
  if (pTail != NULL)  
    pTail->pNext = pNew;
  // Make new node the tail  
  pTail = pNew;  
  // Check to see if new node is also the head (ie. only list entry)  
  if (pHead == NULL)  
  {  
   pHead = pNew;  
    pCurPosition = pNew;  
  }  
}  
//  Find - private method to find the node with the specified app data  
//  attached to it.  
LPNODE CLinkedList::Find(void  *pData)  
{  
  LPNODE pCur;  
  // go thru list until we reach end or we find the right node.  
  for (pCur=pHead; (pCur != NULL) && (pCur->pData != pData); pCur= pCur->pNext);  
  return(pCur);  
}  
//  Insert - create a new node and put it in front of the current  
//  position node and make it the current position.  
void CLinkedList::Insert(void  *pData)  
{  
  LPNODE  pNext, pPrev;  
  LPNODE  pNew = new NODE;  
  pNew->pData = pData;  
  // check to be sure that there is a current node  
  if (pCurPosition != NULL)  
  {  
     
    // get pointers of current position  
   pPrev = pCurPosition->pPrev;  
   pNext = pCurPosition->pNext;  
    // set new nodes pointers for insertion into the list  
    pNew->pPrev = pPrev;  
    pNew->pNext = pCurPosition;  
    // Set the node in front of new node (if any) to point to it  
    if (pPrev != NULL)  
  {  
      pPrev->pNext = pNew;  
    // No node in front -> new node is at head  
    } else {  
     pHead = pNew;  
    }  
   // make new node the current node  
    pCurPosition = pNew;  
  // No current node, just Add to front  
  } else {  
    Add(pData);  
  }  
}  
//  Insert - create a new node and put it in front of the specified  
//  node and make it the current position.  
void CLinkedList::Insert(void *pData, void  *pBefore)  
{  
  // simply make the specified node current and insert the new  
  // node.  
  pCurPosition = Find(pBefore);  
  Insert(pData);  
}  

//  Remove - remove a specified node from the list.  
//  Note: we do not delete the app data attached to the node!  
void CLinkedList::Remove()  
{  
  LPNODE  pCur, pNext, pPrev;  
  pCur = pCurPosition;  
  if (pCur != NULL)  
  {  
   // save a copy of the links  
   pPrev = pCur->pPrev;  
   pNext = pCur->pNext;  
    // Is there a node ahead of us?  
    if (pPrev != NULL)  
  {  
      // yes -> update it to not point to us.  
      pPrev->pNext = pNext;  
    } else {  
      // no -> update head to not point to us.  
     pHead = pNext;  
      pCurPosition = pNext;  
    }  
    // Is there a node behind us?  
    if (pNext != NULL)  
  {  
      // yes -> update it to not point to us.  
      pNext->pPrev = pPrev;  
      pCurPosition = pNext;  
    } else {  
      // no -> update tail to not point to us.  
     pTail = pPrev;  
      pCurPosition = pPrev;  
    }  
    delete(pCur);  
  }  
}    
//  Remove - remove a specified node from the list.  
//  Note: we do not delete the app data attached to the node!  
void CLinkedList::Remove(void  *pData)  
{  
  pCurPosition = Find(pData);  
  Remove();  
}    
//  RemoveFirst - remove the first node in the list and return the  
//  app data associated with it.  
void * CLinkedList::RemoveFirst()  
{  
  LPNODE  pCur, pNext;  
  void  *pData = NULL;  
  pCur = pHead;  
  // is there a node at the head?  
  if (pCur != NULL)  
  {  
   // take first node out of list.  
   pNext = pCur->pNext;  
   pHead = pNext;  
    pCurPosition = pNext;  
    // are there any nodes after us?  
    if (pNext != NULL)  
  {  
      // yes -> make it the new head  
      pNext->pPrev = NULL;  
    } else {  
      // no -> the list is now empty  
     pTail = NULL;  
    }  
    // get app data for node and then delete it  
   pData = pCur->pData;  
    delete(pCur);  
  }  
  return(pData);  
}  
//  RemoveLast - remove the last node in the list and return the  
//  app data associated with it.  
void * CLinkedList::RemoveLast()  
{  
  LPNODE  pCur, pPrev;  
  void  *pData = NULL;  
  pCur = pTail;  
  // is there a node at the tail?  
  if (pCur != NULL)  
  {  
   // take last node out of list.  
   pPrev = pCur->pPrev;  
   pTail = pPrev;  
    // are there any nodes ahead of us?  
    if (pPrev != NULL)  
  {  
      // yes -> make it the new tail node  
      pPrev->pNext = NULL;  
    } else {  
      // no -> list is now empty  
     pHead = NULL;  
      pCurPosition = NULL;  
    }  
    // get app data for node and then delete it  
   pData = pCur->pData;  
    delete(pCur);  
  }  
  return(pData);  
} 

void CLinkedList::SetCurToTail()
{
    pCurPosition = pTail;
}

void* CLinkedList::GetCurrent()
{
    if( pCurPosition )
        return pCurPosition->pData;
    else
        return NULL;
}

int CLinkedList::IsEmpty()
{
    return (pHead==NULL)?1:0;
}

